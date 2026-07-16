package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestParseIgnoredRecipients(t *testing.T) {
	ignored := parseIgnoredRecipients(" partner1@example.com,PARTNER2@example.com ;\n partner3@example.com ")

	for _, address := range []string{
		"partner1@example.com",
		"partner2@example.com",
		"partner3@example.com",
	} {
		if _, ok := ignored.exact[address]; !ok {
			t.Fatalf("expected %q to be ignored", address)
		}
	}
}

func TestShouldIgnoreRecipient(t *testing.T) {
	cfg := config{
		IgnoredRecipients: parseIgnoredRecipients("Partner@example.com"),
	}

	if !shouldIgnoreRecipient(cfg, " partner@example.com ") {
		t.Fatal("expected recipient to be ignored")
	}

	if shouldIgnoreRecipient(cfg, "other@example.com") {
		t.Fatal("did not expect unrelated recipient to be ignored")
	}
}

func TestShouldIgnoreRecipientPattern(t *testing.T) {
	cfg := config{
		IgnoredRecipients: parseIgnoredRecipients("e2e-*, qa+?@example.com"),
	}

	for _, recipient := range []string{
		"e2e-user@example.com",
		"E2E-admin@partner.test",
		"qa+a@example.com",
	} {
		if !shouldIgnoreRecipient(cfg, recipient) {
			t.Fatalf("expected %q to match ignore rules", recipient)
		}
	}

	if shouldIgnoreRecipient(cfg, "prod-user@example.com") {
		t.Fatal("did not expect unrelated recipient to match ignore rules")
	}
}

func TestParseAllowedDomains(t *testing.T) {
	domains := parseAllowedDomains(" @mail.s.example.com ,\n S.EXAMPLE.NET ; ")

	if len(domains) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(domains))
	}
	for _, domain := range []string{"mail.s.example.com", "s.example.net"} {
		if _, ok := domains[domain]; !ok {
			t.Fatalf("expected %q to be allowed", domain)
		}
	}
}

func TestRecipientDomainAllowed(t *testing.T) {
	cfg := config{
		AllowedDomains: parseAllowedDomains("mail.s.example.com,s.example.net"),
	}

	for _, recipient := range []string{
		"user@mail.s.example.com",
		" User@S.Example.NET ",
	} {
		if !recipientDomainAllowed(cfg, recipient) {
			t.Fatalf("expected %q to be allowed", recipient)
		}
	}

	for _, recipient := range []string{
		"user@other.example.org",
		"user@example.com",
		"user@sub.s.example.net",
		"unknown recipient",
	} {
		if recipientDomainAllowed(cfg, recipient) {
			t.Fatalf("did not expect %q to be allowed", recipient)
		}
	}
}

func TestRecipientDomainAllowedWithoutAllowlist(t *testing.T) {
	if !recipientDomainAllowed(config{}, "anyone@anywhere.test") {
		t.Fatal("expected every domain to be allowed when allowlist is empty")
	}
}

func TestPollOnlySendsAllowedDomains(t *testing.T) {
	store := newTestStore(t)
	mailpit := newFakeMailpitClient()

	var sent []otpMessage
	slack := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload otpMessage
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode slack payload: %v", err)
		}
		sent = append(sent, payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer slack.Close()

	for id, domain := range map[string]string{
		"msg-1": "mail.s.example.com",
		"msg-2": "s.example.net",
		"msg-3": "other.example.org",
	} {
		mailpit.addMessage(mailpitMessage{
			ID:      id,
			Subject: "login code",
			Text:    "your code is 123456",
			To:      []mailpitAddress{{Address: "user@" + domain}},
		})
	}

	poll(config{
		SlackWebhookURL:   slack.URL,
		SearchQuery:       "login code",
		AllowedDomains:    parseAllowedDomains("mail.s.example.com,s.example.net"),
		otpRegex:          regexp.MustCompile(`\b\d{6,8}\b`),
		maxMessagesPerRun: 20,
	}, mailpit, store)

	if len(sent) != 2 {
		t.Fatalf("expected 2 OTPs sent to slack, got %d: %+v", len(sent), sent)
	}
	for _, payload := range sent {
		if strings.HasSuffix(payload.Email, "@other.example.org") {
			t.Fatalf("expected disallowed domain to be filtered out, got %q", payload.Email)
		}
		if payload.OTP != "123456" {
			t.Fatalf("expected OTP 123456, got %q", payload.OTP)
		}
	}
	if seen, _ := store.Seen("msg-3"); seen {
		t.Fatal("did not expect disallowed message to be marked processed")
	}
}

func TestHeartbeatMarksUpAndDeletesMessage(t *testing.T) {
	store := newTestStore(t)
	mailpit := newFakeMailpitClient()
	sender := &fakeHeartbeatSender{}
	now := time.Date(2026, 3, 30, 12, 0, 0, 0, time.UTC)

	monitor := newHeartbeatMonitor(heartbeatConfig{
		Enabled:       true,
		Recipient:     "heartbeat@example.com",
		SMTPFromEmail: "heartbeat@example.com",
		SubjectPrefix: "[mailpit2slack] heartbeat",
		Interval:      5 * time.Minute,
		WaitTimeout:   2 * time.Minute,
		MaxAttempts:   3,
	}, mailpit, store, sender)
	monitor.now = func() time.Time { return now }

	monitor.run()
	if len(sender.sent) != 1 {
		t.Fatalf("expected one heartbeat email, got %d", len(sender.sent))
	}

	state, err := store.HeartbeatState()
	if err != nil {
		t.Fatalf("read heartbeat state: %v", err)
	}
	if state.Attempts != 1 {
		t.Fatalf("expected attempts=1, got %d", state.Attempts)
	}
	if state.CurrentToken == "" {
		t.Fatal("expected current token to be stored")
	}

	mailpit.addMessage(mailpitMessage{
		ID:      "hb-1",
		Subject: sender.sent[0].Subject,
		Text:    sender.sent[0].Body,
		To: []mailpitAddress{{
			Address: "heartbeat@example.com",
		}},
	})

	now = now.Add(30 * time.Second)
	monitor.run()

	state, err = store.HeartbeatState()
	if err != nil {
		t.Fatalf("read heartbeat state after delivery: %v", err)
	}
	if state.Status != heartbeatStatusUp {
		t.Fatalf("expected status up, got %q", state.Status)
	}
	if state.Attempts != 0 {
		t.Fatalf("expected attempts reset to 0, got %d", state.Attempts)
	}
	if state.CurrentToken != "" {
		t.Fatalf("expected current token cleared, got %q", state.CurrentToken)
	}
	if !mailpit.wasDeleted("hb-1") {
		t.Fatal("expected delivered heartbeat email to be deleted from mailpit")
	}
}

func TestHeartbeatBecomesWarningThenDownAfterThreeMisses(t *testing.T) {
	store := newTestStore(t)
	mailpit := newFakeMailpitClient()
	sender := &fakeHeartbeatSender{}
	now := time.Date(2026, 3, 30, 12, 0, 0, 0, time.UTC)

	monitor := newHeartbeatMonitor(heartbeatConfig{
		Enabled:       true,
		Recipient:     "heartbeat@example.com",
		SMTPFromEmail: "heartbeat@example.com",
		SubjectPrefix: "[mailpit2slack] heartbeat",
		Interval:      5 * time.Minute,
		WaitTimeout:   1 * time.Minute,
		MaxAttempts:   3,
	}, mailpit, store, sender)
	monitor.now = func() time.Time { return now }

	monitor.run()
	assertHeartbeatState(t, store, heartbeatStatusUnknown, 1)

	now = now.Add(1 * time.Minute)
	monitor.run()
	assertHeartbeatState(t, store, heartbeatStatusWarning, 2)

	now = now.Add(1 * time.Minute)
	monitor.run()
	assertHeartbeatState(t, store, heartbeatStatusWarning, 3)

	now = now.Add(1 * time.Minute)
	monitor.run()
	assertHeartbeatState(t, store, heartbeatStatusDown, 3)

	if len(sender.sent) != 3 {
		t.Fatalf("expected 3 send attempts, got %d", len(sender.sent))
	}
}

func TestHealthHandlerHeartbeatDisabled(t *testing.T) {
	store := newTestStore(t)
	handler := newHealthHandler(config{}, store)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var got healthResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Status != "disabled" {
		t.Fatalf("expected disabled status, got %q", got.Status)
	}
	if got.HeartbeatEnabled {
		t.Fatal("expected heartbeat_enabled=false")
	}
}

func TestHealthHandlerReturnsPersistedHeartbeatState(t *testing.T) {
	store := newTestStore(t)
	err := store.SaveHeartbeatState(heartbeatState{
		Status:         heartbeatStatusWarning,
		Attempts:       2,
		LastSentAt:     time.Date(2026, 3, 30, 12, 0, 0, 0, time.UTC),
		LastDeliveryAt: time.Date(2026, 3, 30, 11, 55, 0, 0, time.UTC),
		LastError:      "heartbeat still missing",
	})
	if err != nil {
		t.Fatalf("save heartbeat state: %v", err)
	}

	handler := newHealthHandler(config{
		Heartbeat: heartbeatConfig{Enabled: true},
	}, store)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", rec.Code)
	}

	var got healthResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Status != heartbeatStatusWarning {
		t.Fatalf("expected status %q, got %q", heartbeatStatusWarning, got.Status)
	}
	if got.Attempts != 2 {
		t.Fatalf("expected attempts=2, got %d", got.Attempts)
	}
	if got.LastError != "heartbeat still missing" {
		t.Fatalf("expected last error in response, got %q", got.LastError)
	}
}

func TestHealthHandlerReturnsOKWhenHeartbeatUp(t *testing.T) {
	store := newTestStore(t)
	err := store.SaveHeartbeatState(heartbeatState{
		Status:         heartbeatStatusUp,
		Attempts:       0,
		LastDeliveryAt: time.Date(2026, 3, 30, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("save heartbeat state: %v", err)
	}

	handler := newHealthHandler(config{
		Heartbeat: heartbeatConfig{Enabled: true},
	}, store)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}

func assertHeartbeatState(t *testing.T, store *processedStore, wantStatus string, wantAttempts int) {
	t.Helper()
	state, err := store.HeartbeatState()
	if err != nil {
		t.Fatalf("read heartbeat state: %v", err)
	}
	if state.Status != wantStatus {
		t.Fatalf("expected status %q, got %q", wantStatus, state.Status)
	}
	if state.Attempts != wantAttempts {
		t.Fatalf("expected attempts %d, got %d", wantAttempts, state.Attempts)
	}
}

func newTestStore(t *testing.T) *processedStore {
	t.Helper()
	store, err := newProcessedStore(filepath.Join(t.TempDir(), "processed.sqlite"))
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.db.Close()
	})
	return store
}

type fakeHeartbeatSender struct {
	sent []heartbeatEmail
	err  error
}

func (f *fakeHeartbeatSender) sendHeartbeat(_ context.Context, email heartbeatEmail) error {
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, email)
	return nil
}

type fakeMailpitClient struct {
	messages map[string]*mailpitMessage
	deleted  []string
}

func newFakeMailpitClient() *fakeMailpitClient {
	return &fakeMailpitClient{messages: make(map[string]*mailpitMessage)}
}

func (f *fakeMailpitClient) addMessage(msg mailpitMessage) {
	copyMsg := msg
	f.messages[msg.ID] = &copyMsg
}

func (f *fakeMailpitClient) searchMessages(query string) ([]mailpitMessageSummary, error) {
	query = strings.ToLower(strings.TrimSpace(query))
	results := make([]mailpitMessageSummary, 0)
	for id, msg := range f.messages {
		if query != "" && !strings.Contains(strings.ToLower(strings.Join([]string{msg.Subject, msg.Text, recipientList(msg.To)}, "\n")), query) {
			continue
		}
		results = append(results, mailpitMessageSummary{ID: id, To: msg.To})
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].ID < results[j].ID
	})
	return results, nil
}

func (f *fakeMailpitClient) getMessage(id string) (*mailpitMessage, error) {
	msg, ok := f.messages[id]
	if !ok {
		return nil, fmt.Errorf("message %s not found", id)
	}
	copyMsg := *msg
	return &copyMsg, nil
}

func (f *fakeMailpitClient) deleteMessages(ids []string) error {
	for _, id := range ids {
		delete(f.messages, id)
		f.deleted = append(f.deleted, id)
	}
	return nil
}

func (f *fakeMailpitClient) wasDeleted(id string) bool {
	for _, deletedID := range f.deleted {
		if deletedID == id {
			return true
		}
	}
	return false
}

func recipientList(addresses []mailpitAddress) string {
	parts := make([]string, 0, len(addresses))
	for _, addr := range addresses {
		if addr.Address != "" {
			parts = append(parts, addr.Address)
			continue
		}
		parts = append(parts, recipientFromSummary(mailpitMessageSummary{To: []mailpitAddress{addr}}))
	}
	return strings.Join(parts, ",")
}
