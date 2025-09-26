package seer

import (
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/Glyph/internal/findings"
)

func TestScanFindsSecrets(t *testing.T) {
	content := `AWS key: AKIAABCDEFGHIJKLMNOP
Slack token: xoxb-123456789012-abcdefghijklmnop
Generic key: api_key = sk_live_a1B2c3D4e5F6g7H8
Google key: AIzaSyA1234567890bcdefGhijklmnopqrstuVw
JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
Email: alerts@example.com`

	ts := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	results := Scan("https://example.com", content, Config{
		Allowlist: []string{"alerts@example.com"},
		Now:       func() time.Time { return ts },
	})

	if len(results) != 5 {
		t.Fatalf("expected 5 findings, got %d", len(results))
	}

	check := func(idx int, wantType string, wantSeverity findings.Severity, wantEvidence string) {
		t.Helper()
		f := results[idx]
		if f.Type != wantType {
			t.Fatalf("finding %d type = %q, want %q", idx, f.Type, wantType)
		}
		if f.Severity != wantSeverity {
			t.Fatalf("finding %d severity = %q, want %q", idx, f.Severity, wantSeverity)
		}
		if f.Evidence != wantEvidence {
			t.Fatalf("finding %d evidence = %q, want %q", idx, f.Evidence, wantEvidence)
		}
		if f.Plugin != "seer" {
			t.Fatalf("finding %d plugin = %q, want seer", idx, f.Plugin)
		}
		if !f.DetectedAt.Time().Equal(ts) {
			t.Fatalf("finding %d timestamp mismatch: %s", idx, f.DetectedAt.Time())
		}
		if f.Metadata["pattern"] != wantType {
			t.Fatalf("finding %d metadata pattern = %q", idx, f.Metadata["pattern"])
		}
		if f.Metadata["redacted_match"] != wantEvidence {
			t.Fatalf("finding %d metadata redaction mismatch", idx)
		}
	}

	check(0, "seer.aws_access_key", findings.SeverityHigh, "AKIA…MNOP")
	check(1, "seer.generic_api_key", findings.SeverityMedium, "sk_l…g7H8")
	if entropy := results[1].Metadata["entropy"]; entropy == "" {
		t.Fatalf("generic finding missing entropy")
	}
	check(2, "seer.google_api_key", findings.SeverityHigh, "AIza…tuVw")
	if entropy := results[2].Metadata["entropy"]; entropy == "" {
		t.Fatalf("google api key missing entropy")
	}
	check(3, "seer.jwt_token", findings.SeverityMedium, "eyJh…sw5c")
	if entropy := results[3].Metadata["entropy"]; entropy == "" {
		t.Fatalf("jwt finding missing entropy")
	}
	if alg := results[3].Metadata["jwt_alg"]; alg != "HS256" {
		t.Fatalf("jwt finding missing alg metadata: %q", alg)
	}
	check(4, "seer.slack_token", findings.SeverityHigh, "xoxb…mnop")
}

func TestEntropyFloorsSuppressLowEntropyTokens(t *testing.T) {
	content := `Generic: api_key = aaaaaaaaaaaaaaaa
Google: AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`

	results := Scan("https://example.com", content, Config{})
	if len(results) != 0 {
		t.Fatalf("expected no findings for low-entropy tokens, got %d", len(results))
	}
}

func TestScanDeduplicatesAndRedactsEmails(t *testing.T) {
	content := `Contact us: security@example.com or SECURITY@example.com`
	ts := time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)

	results := Scan("https://example.com", content, Config{Now: func() time.Time { return ts }})
	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}
	f := results[0]
	if f.Type != "seer.email_address" {
		t.Fatalf("email finding type = %q", f.Type)
	}
	if f.Evidence != "secu…@….com" {
		t.Fatalf("email evidence = %q", f.Evidence)
	}
	if got := f.Metadata["domain"]; got != "example.com" {
		t.Fatalf("email metadata domain = %q", got)
	}
}

func TestAllowlistControls(t *testing.T) {
	target := "https://example.com/settings"
	content := `AWS: AKIAABCDEFGHIJKLMNOP
Email: alerts@corp.example.com
Slack: xoxb-123456789012-abcdefghijklmnop`

	results := Scan(target, content, Config{
		Allowlist: []string{"pattern:seer.aws_access_key", "@example.com"},
	})

	if len(results) != 1 {
		t.Fatalf("expected 1 finding after allowlists, got %d", len(results))
	}
	if results[0].Type != "seer.slack_token" {
		t.Fatalf("remaining finding type = %q", results[0].Type)
	}

	cfg := Config{Allowlist: []string{"pattern:seer.aws_access_key", "@example.com", "path:/settings"}}
	if res := Scan(target, content, cfg); len(res) != 0 {
		t.Fatalf("path allowlist should suppress all findings, got %d", len(res))
	}

	cfg.Allowlist = []string{"url:https://example.com/settings"}
	if res := Scan(target, content, cfg); len(res) != 0 {
		t.Fatalf("url allowlist should suppress all findings, got %d", len(res))
	}
}

func TestScanSkipsBinaryContent(t *testing.T) {
	blob := string([]byte{0x00, 0x01, 0x02, 'A', 'K', 'I', 'A'})
	if res := Scan("https://example.com", blob, Config{}); len(res) != 0 {
		t.Fatalf("expected binary content to be skipped, got %d findings", len(res))
	}
}

func TestScanHonoursMaxBytes(t *testing.T) {
	key := "AKIAABCDEFGHIJKLMNOP"
	content := strings.Repeat("A", 200) + "\n" + key

	truncated := Scan("https://example.com", content, Config{MaxScanBytes: 128})
	if len(truncated) != 0 {
		t.Fatalf("expected no findings with strict max bytes, got %d", len(truncated))
	}

	allowed := Scan("https://example.com", content, Config{MaxScanBytes: 256})
	if len(allowed) != 1 {
		t.Fatalf("expected aws key to be detected with higher cap, got %d", len(allowed))
	}
	if allowed[0].Evidence != "AKIA…MNOP" {
		t.Fatalf("unexpected redaction: %q", allowed[0].Evidence)
	}
}
