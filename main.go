package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	heartbeatStateName     = "default"
	heartbeatStatusUnknown = "unknown"
	heartbeatStatusUp      = "up"
	heartbeatStatusWarning = "warning"
	heartbeatStatusDown    = "down"
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

func (c *mailpitClient) request(method, requestPath string, body io.Reader, contentType string) (*http.Response, error) {
	req, err := http.NewRequest(method, c.baseURL+requestPath, body)
	if err != nil {
		return nil, err
	}
	if c.username != "" || c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()
		return nil, fmt.Errorf("mailpit request %s failed: %s (%s)", requestPath, resp.Status, string(responseBody))
	}
	return resp, nil
}

func (c *mailpitClient) searchMessages(query string) ([]mailpitMessageSummary, error) {
	fullURL := "/api/v1/search?query=" + url.QueryEscape(query)
	resp, err := c.request(http.MethodGet, fullURL, nil, "")
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
	resp, err := c.request(http.MethodGet, "/api/v1/message/"+id, nil, "")
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

func (c *mailpitClient) deleteMessages(ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	payload, err := json.Marshal(map[string][]string{"IDs": ids})
	if err != nil {
		return err
	}
	resp, err := c.request(http.MethodDelete, "/api/v1/messages", bytes.NewReader(payload), "application/json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

type heartbeatConfig struct {
	Enabled       bool
	Recipient     string
	SMTPHost      string
	SMTPPort      int
	SMTPUsername  string
	SMTPPassword  string
	SMTPFromEmail string
	SubjectPrefix string
	Interval      time.Duration
	WaitTimeout   time.Duration
	MaxAttempts   int
}

type healthServerConfig struct {
	Addr string
}

type config struct {
	MailpitURL        string
	MailpitUsername   string
	MailpitPassword   string
	SlackWebhookURL   string
	SearchQuery       string
	IgnoredRecipients ignoreRules
	PollInterval      time.Duration
	ProcessedDB       string
	LogLevel          log.Level
	Heartbeat         heartbeatConfig
	HealthServer      healthServerConfig
	otpRegex          *regexp.Regexp
	maxMessagesPerRun int
}

func loadConfig() (config, error) {
	otpPattern := getEnvOrDefault("OTP_REGEX", `\b\d{6,8}\b`)
	regex, err := regexp.Compile(otpPattern)
	if err != nil {
		return config{}, fmt.Errorf("invalid OTP_REGEX: %w", err)
	}

	pollSeconds, err := envPositiveInt("POLL_INTERVAL_SECONDS", 10)
	if err != nil {
		return config{}, err
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
		parsed, err := strconv.Atoi(val)
		if err != nil || parsed <= 0 {
			return config{}, errors.New("MAX_MESSAGES_PER_POLL must be a positive integer")
		}
		maxMessages = parsed
	}

	heartbeat, err := loadHeartbeatConfig()
	if err != nil {
		return config{}, err
	}

	return config{
		MailpitURL:        os.Getenv("MAILPIT_URL"),
		MailpitUsername:   os.Getenv("MAILPIT_USERNAME"),
		MailpitPassword:   os.Getenv("MAILPIT_PASSWORD"),
		SlackWebhookURL:   os.Getenv("SLACK_WEBHOOK_URL"),
		SearchQuery:       searchQuery,
		IgnoredRecipients: parseIgnoredRecipients(os.Getenv("IGNORED_EMAIL_ADDRESSES")),
		PollInterval:      time.Duration(pollSeconds) * time.Second,
		ProcessedDB:       getEnvOrDefault("PROCESSED_DB_PATH", filepath.Join("db", "processed.sqlite")),
		LogLevel:          parsedLevel,
		Heartbeat:         heartbeat,
		HealthServer: healthServerConfig{
			Addr: getEnvOrDefault("HEALTHZ_ADDR", ":8080"),
		},
		otpRegex:          regex,
		maxMessagesPerRun: maxMessages,
	}, nil
}

func loadHeartbeatConfig() (heartbeatConfig, error) {
	enabled, err := envBool("HEARTBEAT_ENABLED", false)
	if err != nil {
		return heartbeatConfig{}, err
	}
	if !enabled {
		return heartbeatConfig{}, nil
	}

	intervalMinutes, err := envPositiveInt("HEARTBEAT_INTERVAL_MINUTES", 5)
	if err != nil {
		return heartbeatConfig{}, err
	}
	waitMinutes, err := envPositiveInt("HEARTBEAT_WAIT_MINUTES", intervalMinutes)
	if err != nil {
		return heartbeatConfig{}, err
	}
	maxAttempts, err := envPositiveInt("HEARTBEAT_MAX_ATTEMPTS", 3)
	if err != nil {
		return heartbeatConfig{}, err
	}

	smtpPort, err := envPositiveInt("HEARTBEAT_SMTP_PORT", 587)
	if err != nil {
		return heartbeatConfig{}, err
	}
	cfg := heartbeatConfig{
		Enabled:       true,
		Recipient:     getEnvOrDefault("HEARTBEAT_RECIPIENT_EMAIL", "heartbeat@example.com"),
		SMTPHost:      os.Getenv("HEARTBEAT_SMTP_HOST"),
		SMTPPort:      smtpPort,
		SMTPUsername:  os.Getenv("HEARTBEAT_SMTP_USERNAME"),
		SMTPPassword:  os.Getenv("HEARTBEAT_SMTP_PASSWORD"),
		SMTPFromEmail: os.Getenv("HEARTBEAT_SMTP_FROM_EMAIL"),
		SubjectPrefix: getEnvOrDefault("HEARTBEAT_SUBJECT_PREFIX", "[mailpit2slack] heartbeat"),
		Interval:      time.Duration(intervalMinutes) * time.Minute,
		WaitTimeout:   time.Duration(waitMinutes) * time.Minute,
		MaxAttempts:   maxAttempts,
	}
	if cfg.SMTPHost == "" {
		return heartbeatConfig{}, errors.New("HEARTBEAT_SMTP_HOST is required when HEARTBEAT_ENABLED=true")
	}
	if cfg.SMTPFromEmail == "" {
		return heartbeatConfig{}, errors.New("HEARTBEAT_SMTP_FROM_EMAIL is required when HEARTBEAT_ENABLED=true")
	}
	if cfg.Recipient == "" {
		return heartbeatConfig{}, errors.New("HEARTBEAT_RECIPIENT_EMAIL is required when HEARTBEAT_ENABLED=true")
	}
	if cfg.SubjectPrefix == "" {
		return heartbeatConfig{}, errors.New("HEARTBEAT_SUBJECT_PREFIX cannot be empty")
	}
	return cfg, nil
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

	req, err := http.NewRequest(http.MethodPost, webhook, bytes.NewReader(body))
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
	for _, content := range contents {
		matches := fallbackRe.FindAllString(content, -1)
		for _, match := range matches {
			digits := digitOnly(match)
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

type ignoreRules struct {
	exact    map[string]struct{}
	patterns []string
}

func parseIgnoredRecipients(raw string) ignoreRules {
	ignored := ignoreRules{
		exact: make(map[string]struct{}),
	}
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n'
	}) {
		normalized := normalizeEmailAddress(part)
		if normalized == "" {
			continue
		}
		if strings.ContainsAny(normalized, "*?[") {
			ignored.patterns = append(ignored.patterns, normalized)
			continue
		}
		ignored.exact[normalized] = struct{}{}
	}
	return ignored
}

func normalizeEmailAddress(address string) string {
	return strings.ToLower(strings.TrimSpace(address))
}

func shouldIgnoreRecipient(cfg config, recipient string) bool {
	normalized := normalizeEmailAddress(recipient)
	if normalized == "" {
		return false
	}
	if _, ignored := cfg.IgnoredRecipients.exact[normalized]; ignored {
		return true
	}
	for _, pattern := range cfg.IgnoredRecipients.patterns {
		matched, err := path.Match(pattern, normalized)
		if err == nil && matched {
			return true
		}
	}
	return false
}

func getEnvOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getFirstEnv(keys ...string) string {
	for _, key := range keys {
		if value := os.Getenv(key); value != "" {
			return value
		}
	}
	return ""
}

func envPositiveInt(key string, fallback int) (int, error) {
	if value := os.Getenv(key); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed <= 0 {
			return 0, fmt.Errorf("%s must be a positive integer", key)
		}
		return parsed, nil
	}
	return fallback, nil
}

func envBool(key string, fallback bool) (bool, error) {
	if value := os.Getenv(key); value != "" {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return false, fmt.Errorf("%s must be a boolean", key)
		}
		return parsed, nil
	}
	return fallback, nil
}

type processedStore struct {
	db *sql.DB
}

type heartbeatState struct {
	Status         string
	Attempts       int
	CurrentToken   string
	CurrentSubject string
	LastSentAt     time.Time
	LastDeliveryAt time.Time
	LastError      string
}

func newProcessedStore(dbPath string) (*processedStore, error) {
	if dir := filepath.Dir(dbPath); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS processed (
		id TEXT PRIMARY KEY,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`); err != nil {
		return nil, err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS heartbeat_state (
		name TEXT PRIMARY KEY,
		status TEXT NOT NULL,
		attempts INTEGER NOT NULL DEFAULT 0,
		current_token TEXT NOT NULL DEFAULT '',
		current_subject TEXT NOT NULL DEFAULT '',
		last_sent_at TEXT NOT NULL DEFAULT '',
		last_delivery_at TEXT NOT NULL DEFAULT '',
		last_error TEXT NOT NULL DEFAULT '',
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

func (s *processedStore) HeartbeatState() (heartbeatState, error) {
	var rawLastSent, rawLastDelivery string
	state := heartbeatState{Status: heartbeatStatusUnknown}
	err := s.db.QueryRow(`SELECT status, attempts, current_token, current_subject, last_sent_at, last_delivery_at, last_error
		FROM heartbeat_state WHERE name = ? LIMIT 1`, heartbeatStateName).Scan(
		&state.Status,
		&state.Attempts,
		&state.CurrentToken,
		&state.CurrentSubject,
		&rawLastSent,
		&rawLastDelivery,
		&state.LastError,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return state, nil
	}
	if err != nil {
		return heartbeatState{}, err
	}
	state.LastSentAt = parseStoredTime(rawLastSent)
	state.LastDeliveryAt = parseStoredTime(rawLastDelivery)
	return state, nil
}

func (s *processedStore) SaveHeartbeatState(state heartbeatState) error {
	if state.Status == "" {
		state.Status = heartbeatStatusUnknown
	}
	_, err := s.db.Exec(`INSERT INTO heartbeat_state (
		name, status, attempts, current_token, current_subject, last_sent_at, last_delivery_at, last_error, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	ON CONFLICT(name) DO UPDATE SET
		status = excluded.status,
		attempts = excluded.attempts,
		current_token = excluded.current_token,
		current_subject = excluded.current_subject,
		last_sent_at = excluded.last_sent_at,
		last_delivery_at = excluded.last_delivery_at,
		last_error = excluded.last_error,
		updated_at = CURRENT_TIMESTAMP`,
		heartbeatStateName,
		state.Status,
		state.Attempts,
		state.CurrentToken,
		state.CurrentSubject,
		formatStoredTime(state.LastSentAt),
		formatStoredTime(state.LastDeliveryAt),
		state.LastError,
	)
	return err
}

func formatStoredTime(ts time.Time) string {
	if ts.IsZero() {
		return ""
	}
	return ts.UTC().Format(time.RFC3339Nano)
}

func parseStoredTime(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

type healthResponse struct {
	Status           string `json:"status"`
	HeartbeatEnabled bool   `json:"heartbeat_enabled"`
	Attempts         int    `json:"attempts,omitempty"`
	LastSentAt       string `json:"last_sent_at,omitempty"`
	LastDeliveryAt   string `json:"last_delivery_at,omitempty"`
	LastError        string `json:"last_error,omitempty"`
}

func newHealthHandler(cfg config, store *processedStore) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if !cfg.Heartbeat.Enabled {
			_ = json.NewEncoder(w).Encode(healthResponse{
				Status:           "disabled",
				HeartbeatEnabled: false,
			})
			return
		}

		state, err := store.HeartbeatState()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status": "error",
				"error":  err.Error(),
			})
			return
		}

		statusCode := http.StatusOK
		if state.Status == heartbeatStatusWarning || state.Status == heartbeatStatusDown {
			statusCode = http.StatusServiceUnavailable
		}
		w.WriteHeader(statusCode)

		_ = json.NewEncoder(w).Encode(healthResponse{
			Status:           state.Status,
			HeartbeatEnabled: true,
			Attempts:         state.Attempts,
			LastSentAt:       formatStoredTime(state.LastSentAt),
			LastDeliveryAt:   formatStoredTime(state.LastDeliveryAt),
			LastError:        state.LastError,
		})
	})
	return mux
}

func startHealthServer(cfg config, store *processedStore) {
	server := &http.Server{
		Addr:              cfg.HealthServer.Addr,
		Handler:           newHealthHandler(cfg, store),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.WithField("addr", cfg.HealthServer.Addr).Info("starting health server")
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.WithError(err).Fatal("health server error")
		}
	}()
}

type mailpitAPI interface {
	searchMessages(query string) ([]mailpitMessageSummary, error)
	getMessage(id string) (*mailpitMessage, error)
	deleteMessages(ids []string) error
}

type heartbeatEmail struct {
	From    string
	To      string
	Subject string
	Body    string
}

type heartbeatEmailSender interface {
	sendHeartbeat(ctx context.Context, email heartbeatEmail) error
}

type smtpHeartbeatSender struct {
	host     string
	port     int
	username string
	password string
}

func newSMTPHeartbeatSender(cfg heartbeatConfig) *smtpHeartbeatSender {
	return &smtpHeartbeatSender{
		host:     cfg.SMTPHost,
		port:     cfg.SMTPPort,
		username: cfg.SMTPUsername,
		password: cfg.SMTPPassword,
	}
}

func (s *smtpHeartbeatSender) sendHeartbeat(ctx context.Context, email heartbeatEmail) error {
	_ = ctx

	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	var auth smtp.Auth
	if s.username != "" {
		auth = smtp.PlainAuth("", s.username, s.password, s.host)
	}

	message := strings.Join([]string{
		fmt.Sprintf("From: %s", email.From),
		fmt.Sprintf("To: %s", email.To),
		fmt.Sprintf("Subject: %s", email.Subject),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		email.Body,
	}, "\r\n")

	if err := smtp.SendMail(addr, auth, email.From, []string{email.To}, []byte(message)); err != nil {
		return fmt.Errorf("send heartbeat email via SMTP: %w", err)
	}
	return nil
}

type heartbeatMonitor struct {
	cfg    heartbeatConfig
	client mailpitAPI
	store  *processedStore
	sender heartbeatEmailSender
	now    func() time.Time
}

func newHeartbeatMonitor(cfg heartbeatConfig, client mailpitAPI, store *processedStore, sender heartbeatEmailSender) *heartbeatMonitor {
	return &heartbeatMonitor{
		cfg:    cfg,
		client: client,
		store:  store,
		sender: sender,
		now:    time.Now,
	}
}

func (m *heartbeatMonitor) run() {
	if m == nil || !m.cfg.Enabled {
		return
	}

	state, err := m.store.HeartbeatState()
	if err != nil {
		log.WithError(err).Error("heartbeat state read error")
		return
	}

	delivered, deletedCount, err := m.consumeHeartbeatMessages(state.CurrentToken)
	if err != nil {
		log.WithError(err).Error("heartbeat mailbox check error")
	} else if delivered {
		state.Status = heartbeatStatusUp
		state.Attempts = 0
		state.CurrentToken = ""
		state.CurrentSubject = ""
		state.LastDeliveryAt = m.now().UTC()
		state.LastError = ""
		if err := m.store.SaveHeartbeatState(state); err != nil {
			log.WithError(err).Error("heartbeat state save error")
			return
		}
		log.WithFields(log.Fields{
			"deleted_messages": deletedCount,
			"delivered_at":     state.LastDeliveryAt.Format(time.RFC3339),
			"status":           state.Status,
		}).Info("heartbeat email received")
		return
	}

	now := m.now().UTC()
	if state.CurrentToken == "" {
		if !m.shouldStartCycle(state, now) {
			return
		}
		state.CurrentToken = buildHeartbeatToken(now)
		state.CurrentSubject = m.buildSubject(state.CurrentToken)
		state.Attempts = 0
		state.LastError = ""
	}

	if state.Attempts >= m.cfg.MaxAttempts {
		state.Status = heartbeatStatusDown
		state.LastError = fmt.Sprintf("heartbeat not received after %d attempts", m.cfg.MaxAttempts)
		state.CurrentToken = ""
		state.CurrentSubject = ""
		if err := m.store.SaveHeartbeatState(state); err != nil {
			log.WithError(err).Error("heartbeat state save error")
			return
		}
		log.WithField("status", state.Status).Error(state.LastError)
		return
	}

	if !state.LastSentAt.IsZero() && now.Sub(state.LastSentAt) < m.cfg.WaitTimeout {
		return
	}

	attemptNumber := state.Attempts + 1
	if attemptNumber > 1 {
		state.Status = heartbeatStatusWarning
		state.LastError = fmt.Sprintf("heartbeat still missing after %d attempt(s)", state.Attempts)
	}

	email := heartbeatEmail{
		From:    m.cfg.SMTPFromEmail,
		To:      m.cfg.Recipient,
		Subject: state.CurrentSubject,
		Body: fmt.Sprintf(
			"mailpit2slack heartbeat\n\ntoken=%s\nattempt=%d\nsent_at=%s\n",
			state.CurrentToken,
			attemptNumber,
			now.Format(time.RFC3339),
		),
	}
	if err := m.sender.sendHeartbeat(context.Background(), email); err != nil {
		state.Attempts = attemptNumber
		state.LastSentAt = now
		state.LastError = err.Error()
		if state.Attempts >= m.cfg.MaxAttempts {
			state.Status = heartbeatStatusDown
			state.CurrentToken = ""
			state.CurrentSubject = ""
		} else if state.Status == heartbeatStatusUnknown {
			state.Status = heartbeatStatusWarning
		}
		if saveErr := m.store.SaveHeartbeatState(state); saveErr != nil {
			log.WithError(saveErr).Error("heartbeat state save error")
			return
		}
		log.WithError(err).WithFields(log.Fields{
			"attempt": attemptNumber,
			"status":  state.Status,
		}).Error("heartbeat send error")
		return
	}

	state.Attempts = attemptNumber
	state.LastSentAt = now
	if err := m.store.SaveHeartbeatState(state); err != nil {
		log.WithError(err).Error("heartbeat state save error")
		return
	}
	log.WithFields(log.Fields{
		"attempt": attemptNumber,
		"to":      m.cfg.Recipient,
		"status":  state.Status,
		"subject": state.CurrentSubject,
	}).Info("heartbeat email sent")
}

func (m *heartbeatMonitor) shouldStartCycle(state heartbeatState, now time.Time) bool {
	lastReference := state.LastDeliveryAt
	if lastReference.IsZero() || state.LastSentAt.After(lastReference) {
		lastReference = state.LastSentAt
	}
	if lastReference.IsZero() {
		return true
	}
	return now.Sub(lastReference) >= m.cfg.Interval
}

func buildHeartbeatToken(now time.Time) string {
	return fmt.Sprintf("%d", now.UTC().UnixNano())
}

func (m *heartbeatMonitor) buildSubject(token string) string {
	return fmt.Sprintf("%s %s", m.cfg.SubjectPrefix, token)
}

func (m *heartbeatMonitor) consumeHeartbeatMessages(currentToken string) (bool, int, error) {
	messages, err := m.client.searchMessages(m.cfg.Recipient)
	if err != nil {
		return false, 0, err
	}

	idsToDelete := make([]string, 0)
	delivered := false
	for _, summary := range messages {
		msg, err := m.client.getMessage(summary.ID)
		if err != nil {
			return false, 0, err
		}
		if !isHeartbeatMessage(m.cfg, msg) {
			continue
		}
		idsToDelete = append(idsToDelete, summary.ID)
		if currentToken != "" && heartbeatMatchesToken(msg, currentToken) {
			delivered = true
		}
	}
	if err := m.client.deleteMessages(idsToDelete); err != nil {
		return false, 0, err
	}
	return delivered, len(idsToDelete), nil
}

func isHeartbeatMessage(cfg heartbeatConfig, msg *mailpitMessage) bool {
	if !cfg.Enabled || msg == nil {
		return false
	}
	if !messageHasRecipient(msg, cfg.Recipient) {
		return false
	}
	return strings.HasPrefix(msg.Subject, cfg.SubjectPrefix)
}

func heartbeatMatchesToken(msg *mailpitMessage, token string) bool {
	if msg == nil || token == "" {
		return false
	}
	combined := strings.Join([]string{msg.Subject, msg.Text, stripHTML(msg.HTML)}, "\n")
	return strings.Contains(combined, token)
}

func messageHasRecipient(msg *mailpitMessage, recipient string) bool {
	target := normalizeEmailAddress(recipient)
	if target == "" {
		return false
	}
	for _, addr := range msg.To {
		candidate := normalizeEmailAddress(addr.Address)
		if candidate == "" {
			candidate = normalizeEmailAddress(recipientFromSummary(mailpitMessageSummary{To: []mailpitAddress{addr}}))
		}
		if candidate == target {
			return true
		}
	}
	return false
}

func poll(cfg config, client *mailpitClient, store *processedStore) {
	log.Info("checking mailpit for messages")
	messages, err := client.searchMessages(cfg.SearchQuery)
	if err != nil {
		log.WithError(err).Error("search error")
		return
	}
	log.Debugf("found %d messages matching query", len(messages))

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
		if isHeartbeatMessage(cfg.Heartbeat, msg) {
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
		if shouldIgnoreRecipient(cfg, recipient) {
			if err := store.Mark(summary.ID); err != nil {
				log.WithError(err).Error("failed to mark ignored message processed")
				continue
			}
			log.WithFields(log.Fields{
				"email":  recipient,
				"msg_id": summary.ID,
			}).Info("ignored recipient")
			continue
		}

		payload := formatSlackMessage(recipient, otp)
		if err := sendToSlack(cfg.SlackWebhookURL, payload); err != nil {
			log.WithError(err).Error("slack error")
			continue
		}
		if err := store.Mark(summary.ID); err != nil {
			log.WithError(err).Error("failed to mark processed")
			continue
		}
		log.WithFields(log.Fields{
			"otp":    otp,
			"email":  recipient,
			"msg_id": summary.ID,
		}).Info("sent OTP to Slack")
	}
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

	startHealthServer(cfg, store)

	var heartbeat *heartbeatMonitor
	if cfg.Heartbeat.Enabled {
		sender := newSMTPHeartbeatSender(cfg.Heartbeat)
		heartbeat = newHeartbeatMonitor(cfg.Heartbeat, client, store, sender)
	}

	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	log.Info("starting mailpit -> slack forwarder")
	if heartbeat != nil {
		heartbeat.run()
	}
	poll(cfg, client, store)

	for range ticker.C {
		if heartbeat != nil {
			heartbeat.run()
		}
		poll(cfg, client, store)
	}
}
