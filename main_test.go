package main

import "testing"

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
