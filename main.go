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

	"database/sql"

	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
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
	ProcessedDB       string
	LogLevel          log.Level
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

	logLevelStr := strings.ToLower(getEnvOrDefault("LOG_LEVEL", "info"))
	parsedLevel, err := log.ParseLevel(logLevelStr)
	if err != nil {
		return config{}, fmt.Errorf("invalid LOG_LEVEL: %w", err)
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
		ProcessedDB:       getEnvOrDefault("PROCESSED_DB_PATH", filepath.Join("db", "processed.sqlite")),
		LogLevel:          parsedLevel,
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

type processedStore struct {
	db *sql.DB
}

func newProcessedStore(path string) (*processedStore, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS processed (
		id TEXT PRIMARY KEY,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`); err != nil {
		return nil, err
	}
	return &processedStore{db: db}, nil
}

func (s *processedStore) Seen(id string) (bool, error) {
	var tmp string
	err := s.db.QueryRow("SELECT id FROM processed WHERE id = ? LIMIT 1", id).Scan(&tmp)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *processedStore) Mark(id string) error {
	_, err := s.db.Exec("INSERT OR IGNORE INTO processed(id) VALUES(?)", id)
	return err
}

func poll(cfg config, client *mailpitClient, store *processedStore) {
	log.Info("checking mailpit for messages")
	messages, err := client.searchMessages(cfg.SearchQuery)
	if err != nil {
		log.WithError(err).Error("search error")
		return
	}
	log.Debugf("found %d messages matching query", len(messages))

	changed := false
	for i, summary := range messages {
		if i >= cfg.maxMessagesPerRun {
			break
		}
		seen, err := store.Seen(summary.ID)
		if err != nil {
			log.WithError(err).Error("processed check error")
			continue
		}
		if seen {
			continue
		}

		msg, err := client.getMessage(summary.ID)
		if err != nil {
			log.WithError(err).Error("get message error")
			continue
		}

		otp := extractOTP(msg, cfg.otpRegex)
		if otp == "" {
			log.WithFields(log.Fields{
				"message_id": summary.ID,
				"subject":    msg.Subject,
			}).Warn("no OTP found in message")
			continue
		}

		recipient := recipientFromSummary(summary)
		payload := formatSlackMessage(recipient, otp)
		if err := sendToSlack(cfg.SlackWebhookURL, payload); err != nil {
			log.WithError(err).Error("slack error")
			continue
		}
		if err := store.Mark(summary.ID); err != nil {
			log.WithError(err).Error("failed to mark processed")
			continue
		}
		changed = true
		log.WithFields(log.Fields{
			"otp":    otp,
			"email":  recipient,
			"msg_id": summary.ID,
		}).Info("sent OTP to Slack")
	}
	_ = changed
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.WithError(err).Error("config error")
		os.Exit(1)
	}
	if err := validateConfig(cfg); err != nil {
		log.WithError(err).Error("config error")
		os.Exit(1)
	}

	log.SetFormatter(&log.JSONFormatter{TimestampFormat: time.RFC3339})
	log.SetLevel(cfg.LogLevel)

	client := newMailpitClient(cfg.MailpitURL, cfg.MailpitUsername, cfg.MailpitPassword)
	store, err := newProcessedStore(cfg.ProcessedDB)
	if err != nil {
		log.WithError(err).Error("db error")
		os.Exit(1)
	}

	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	log.Info("starting mailpit -> slack forwarder")
	poll(cfg, client, store)

	for range ticker.C {
		poll(cfg, client, store)
	}
}
