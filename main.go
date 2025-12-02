package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type mailpitAddress struct {
	Mailbox string `json:"Mailbox"`
	Domain  string `json:"Domain"`
	Address string `json:"Address"`
	Name    string `json:"Name"`
}

type mailpitMessageSummary struct {
	ID      string           `json:"ID"`
	To      []mailpitAddress `json:"To"`
	Created string           `json:"Created"`
}

type mailpitMessage struct {
	ID      string            `json:"ID"`
	Subject string            `json:"Subject"`
	Text    string            `json:"Text"`
	HTML    string            `json:"HTML"`
	To      []mailpitAddress  `json:"To"`
	From    map[string]string `json:"From"`
}

type mailpitSearchResponse struct {
	Messages []mailpitMessageSummary `json:"messages"`
}

type mailpitClient struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
}

func newMailpitClient(baseURL, username, password string) *mailpitClient {
	return &mailpitClient{
		baseURL:    strings.TrimSuffix(baseURL, "/"),
		username:   username,
		password:   password,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *mailpitClient) request(method, path string) (*http.Response, error) {
	req, err := http.NewRequest(method, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if c.username != "" || c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()
		return nil, fmt.Errorf("mailpit request %s failed: %s (%s)", path, resp.Status, string(body))
	}
	return resp, nil
}

func (c *mailpitClient) searchMessages(query string) ([]mailpitMessageSummary, error) {
	fullUrl := "/api/v1/search?query=" + url.QueryEscape(query)
	resp, err := c.request("GET", fullUrl)
	fmt.Println("Query:", fullUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var parsed mailpitSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	return parsed.Messages, nil
}

func (c *mailpitClient) getMessage(id string) (*mailpitMessage, error) {
	resp, err := c.request("GET", "/api/v1/message/"+id)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var msg mailpitMessage
	if err := json.NewDecoder(resp.Body).Decode(&msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

type config struct {
	MailpitURL        string
	MailpitUsername   string
	MailpitPassword   string
	SlackWebhookURL   string
	SearchQuery       string
	PollInterval      time.Duration
	ProcessedFile     string
	otpRegex          *regexp.Regexp
	maxMessagesPerRun int
}

func loadConfig() (config, error) {
	otpPattern := getEnvOrDefault("OTP_REGEX", `\b\d{6,8}\b`)
	regex, err := regexp.Compile(otpPattern)
	if err != nil {
		return config{}, fmt.Errorf("invalid OTP_REGEX: %w", err)
	}

	pollSeconds := getEnvOrDefault("POLL_INTERVAL_SECONDS", "10")
	interval, err := strconv.Atoi(pollSeconds)
	if err != nil || interval <= 0 {
		return config{}, errors.New("POLL_INTERVAL_SECONDS must be a positive integer")
	}

	searchQuery := os.Getenv("MAILPIT_SEARCH_QUERY")
	if searchQuery == "" {
		searchQuery = os.Getenv("TEST_EMAIL_DOMAIN")
	}
	if searchQuery == "" {
		return config{}, errors.New("MAILPIT_SEARCH_QUERY or TEST_EMAIL_DOMAIN must be set to filter results")
	}

	maxMessages := 20
	if val := os.Getenv("MAX_MESSAGES_PER_POLL"); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil && parsed > 0 {
			maxMessages = parsed
		}
	}

	return config{
		MailpitURL:        os.Getenv("MAILPIT_URL"),
		MailpitUsername:   os.Getenv("MAILPIT_USERNAME"),
		MailpitPassword:   os.Getenv("MAILPIT_PASSWORD"),
		SlackWebhookURL:   os.Getenv("SLACK_WEBHOOK_URL"),
		SearchQuery:       searchQuery,
		PollInterval:      time.Duration(interval) * time.Second,
		ProcessedFile:     getEnvOrDefault("PROCESSED_STORE_FILE", filepath.Join("db", "processed_ids.txt")),
		otpRegex:          regex,
		maxMessagesPerRun: maxMessages,
	}, nil
}

func validateConfig(cfg config) error {
	if cfg.MailpitURL == "" {
		return errors.New("MAILPIT_URL is required")
	}
	if cfg.SlackWebhookURL == "" {
		return errors.New("SLACK_WEBHOOK_URL is required")
	}
	return nil
}

type otpMessage struct {
	Email string `json:"email"`
	OTP   string `json:"otp"`
}

func sendToSlack(webhook string, payload otpMessage) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", webhook, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("slack webhook failed: %s (%s)", resp.Status, string(respBody))
	}
	return nil
}

func formatSlackMessage(recipient, otp string) otpMessage {
	return otpMessage{
		Email: recipient,
		OTP:   otp,
	}
}

func extractOTP(msg *mailpitMessage, regex *regexp.Regexp) string {
	if msg == nil {
		return ""
	}
	if otp := regex.FindString(msg.Text); otp != "" {
		return otp
	}
	if otp := regex.FindString(stripHTML(msg.HTML)); otp != "" {
		return otp
	}
	if otp := regex.FindString(msg.Subject); otp != "" {
		return otp
	}
	if otp := extractDigitsFallback([]string{msg.Text, stripHTML(msg.HTML), msg.Subject}); otp != "" {
		return otp
	}
	return ""
}

// extractDigitsFallback handles cases where digits may be spaced or contain other characters.
func extractDigitsFallback(contents []string) string {
	fallbackRe := regexp.MustCompile(`(\d[\d\s-]{5,})`)
	for _, c := range contents {
		matches := fallbackRe.FindAllString(c, -1)
		for _, m := range matches {
			digits := digitOnly(m)
			if len(digits) >= 6 && len(digits) <= 10 {
				return digits
			}
		}
	}
	return ""
}

func digitOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func stripHTML(html string) string {
	if html == "" {
		return ""
	}
	tagRe := regexp.MustCompile("<[^>]*>")
	return tagRe.ReplaceAllString(html, " ")
}

func recipientFromSummary(summary mailpitMessageSummary) string {
	if len(summary.To) == 0 {
		return "unknown recipient"
	}
	addr := summary.To[0]
	if addr.Address != "" {
		return addr.Address
	}
	if addr.Mailbox == "" && addr.Domain == "" {
		return "unknown recipient"
	}
	if addr.Domain == "" {
		return addr.Mailbox
	}
	if addr.Mailbox == "" {
		return addr.Domain
	}
	return addr.Mailbox + "@" + addr.Domain
}

func getEnvOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func loadProcessed(file string) (map[string]struct{}, error) {
	result := make(map[string]struct{})
	data, err := os.ReadFile(file)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return result, nil
		}
		return result, err
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		id := strings.TrimSpace(line)
		if id == "" {
			continue
		}
		result[id] = struct{}{}
	}
	return result, nil
}

func saveProcessed(file string, processed map[string]struct{}) error {
	if dir := filepath.Dir(file); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	var lines []string
	for id := range processed {
		lines = append(lines, id)
	}
	content := strings.Join(lines, "\n")
	return os.WriteFile(file, []byte(content), 0o644)
}

func poll(cfg config, client *mailpitClient, processed map[string]struct{}) {
	fmt.Println("Checking...")
	messages, err := client.searchMessages(cfg.SearchQuery)
	if err != nil {
		fmt.Println("search error:", err)
		return
	}

	// print number of messages found
	fmt.Printf("Found %d messages\n", len(messages))

	changed := false
	for i, summary := range messages {
		if i >= cfg.maxMessagesPerRun {
			break
		}
		if _, seen := processed[summary.ID]; seen {
			continue
		}

		msg, err := client.getMessage(summary.ID)
		if err != nil {
			fmt.Println("get message error:", err)
			continue
		}

		otp := extractOTP(msg, cfg.otpRegex)
		if otp == "" {
			fmt.Printf("no OTP found in message %s (subject: %q)\n", summary.ID, msg.Subject)
			continue
		}

		recipient := recipientFromSummary(summary)
		payload := formatSlackMessage(recipient, otp)
		if err := sendToSlack(cfg.SlackWebhookURL, payload); err != nil {
			fmt.Println("slack error:", err)
			continue
		}
		processed[summary.ID] = struct{}{}
		changed = true
		fmt.Printf("Sent OTP %s for %s to Slack\n", otp, recipient)
	}

	if changed {
		if err := saveProcessed(cfg.ProcessedFile, processed); err != nil {
			fmt.Println("failed to save processed IDs:", err)
		}
	}
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Println("config error:", err)
		os.Exit(1)
	}
	if err := validateConfig(cfg); err != nil {
		fmt.Println("config error:", err)
		os.Exit(1)
	}

	client := newMailpitClient(cfg.MailpitURL, cfg.MailpitUsername, cfg.MailpitPassword)
	processed, err := loadProcessed(cfg.ProcessedFile)
	if err != nil {
		fmt.Println("warning: could not load processed IDs, starting fresh:", err)
		processed = make(map[string]struct{})
	}

	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	fmt.Println("Starting mailpit -> slack forwarder")
	poll(cfg, client, processed)

	for range ticker.C {
		poll(cfg, client, processed)
	}
}
