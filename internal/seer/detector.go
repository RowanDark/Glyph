package seer

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/RowanDark/Glyph/internal/findings"
)

const (
	defaultEvidencePrefix = 4
	defaultEvidenceSuffix = 4
	defaultMaxScanBytes   = 512 * 1024

	genericKeyMinEntropy = 3.5
	googleKeyMinEntropy  = 3.5
	jwtTokenMinEntropy   = 3.0
)

var (
	awsAccessKeyRe = regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA)[0-9A-Z]{16}\b`)
	slackTokenRe   = regexp.MustCompile(`\bxox(?:b|p|a|r|s)-[0-9A-Za-z-]{10,}\b`)
	genericKeyRe   = regexp.MustCompile(`(?i)(?:api|token|secret|key)[-_ ]*(?:id|key)?\s*[:=]\s*['\"]?([A-Za-z0-9-_]{16,128})['\"]?`)
	googleAPIKeyRe = regexp.MustCompile(`\bAIza[0-9A-Za-z-_]{35}\b`)
	jwtTokenRe     = regexp.MustCompile(`\b([A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]{8,})\b`)
	emailRe        = regexp.MustCompile(`\b([A-Za-z0-9](?:[A-Za-z0-9.!#$%&'*+/=?^_\x60{|}~-]{0,63}))@((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:[A-Za-z]{2,24}))\b`)
)

// Config controls how the detector scans text for potential secrets.
type Config struct {
	Allowlist      []string
	Now            func() time.Time
	EvidencePrefix int
	EvidenceSuffix int
	MaxScanBytes   int
}

// Scan analyses the provided content and returns structured findings.
func Scan(target, content string, cfg Config) []findings.Finding {
	allow := buildAllowlist(cfg.Allowlist)
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	maxBytes := cfg.MaxScanBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxScanBytes
	}
	content = clampToValidUTF8(content, maxBytes)
	if looksBinary(content) {
		return nil
	}

	prefix := cfg.EvidencePrefix
	if prefix < 0 {
		prefix = 0
	}
	suffix := cfg.EvidenceSuffix
	if suffix < 0 {
		suffix = 0
	}
	if prefix == 0 && suffix == 0 {
		prefix = defaultEvidencePrefix
		suffix = defaultEvidenceSuffix
	}

	type detection struct {
		match    string
		kind     string
		message  string
		severity findings.Severity
		metadata map[string]string
	}

	var detections []detection
	seen := make(map[string]struct{})

	add := func(match, kind, message string, severity findings.Severity, metadata map[string]string) {
		match = strings.TrimSpace(match)
		if match == "" {
			return
		}
		if shouldAllow(match, kind, target, metadata, allow) {
			return
		}
		key := kind + "|" + strings.ToLower(match)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		meta := map[string]string{"pattern": kind, "match_length": strconv.Itoa(utf8.RuneCountInString(match))}
		for k, v := range metadata {
			meta[k] = v
		}
		redacted := redact(match, prefix, suffix)
		meta["redacted_match"] = redacted
		detections = append(detections, detection{
			match:    match,
			kind:     kind,
			message:  message,
			severity: severity,
			metadata: meta,
		})
	}

	for _, match := range awsAccessKeyRe.FindAllString(content, -1) {
		add(match, "seer.aws_access_key", "Potential AWS access key detected", findings.SeverityHigh, nil)
	}

	for _, match := range slackTokenRe.FindAllString(content, -1) {
		add(match, "seer.slack_token", "Potential Slack token detected", findings.SeverityHigh, nil)
	}

	for _, groups := range genericKeyRe.FindAllStringSubmatch(content, -1) {
		if len(groups) < 2 {
			continue
		}
		candidate := groups[1]
		if awsAccessKeyRe.MatchString(candidate) || slackTokenRe.MatchString(candidate) || googleAPIKeyRe.MatchString(candidate) {
			continue
		}
		entropy := shannonEntropy(candidate)
		if entropy < genericKeyMinEntropy {
			continue
		}
		add(candidate, "seer.generic_api_key", "High-entropy API key candidate detected", findings.SeverityMedium, map[string]string{
			"entropy":           fmt.Sprintf("%.2f", entropy),
			"entropy_threshold": fmt.Sprintf("%.2f", genericKeyMinEntropy),
		})
	}

	for _, match := range googleAPIKeyRe.FindAllString(content, -1) {
		entropy := shannonEntropy(match)
		if entropy < googleKeyMinEntropy {
			continue
		}
		add(match, "seer.google_api_key", "Potential Google API key detected", findings.SeverityHigh, map[string]string{
			"entropy":           fmt.Sprintf("%.2f", entropy),
			"entropy_threshold": fmt.Sprintf("%.2f", googleKeyMinEntropy),
		})
	}

	for _, groups := range jwtTokenRe.FindAllStringSubmatch(content, -1) {
		if len(groups) < 4 {
			continue
		}
		token := groups[0]
		alg, ok := parseJWT(token)
		if !ok {
			continue
		}
		entropy := shannonEntropy(token)
		if entropy < jwtTokenMinEntropy {
			continue
		}
		metadata := map[string]string{
			"entropy":           fmt.Sprintf("%.2f", entropy),
			"entropy_threshold": fmt.Sprintf("%.2f", jwtTokenMinEntropy),
		}
		if alg != "" {
			metadata["jwt_alg"] = alg
		}
		add(token, "seer.jwt_token", "Potential JSON Web Token detected", findings.SeverityMedium, metadata)
	}

	for _, groups := range emailRe.FindAllStringSubmatch(content, -1) {
		if len(groups) < 3 {
			continue
		}
		full := groups[0]
		local := groups[1]
		domain := strings.ToLower(groups[2])
		if utf8.RuneCountInString(local) > 64 {
			continue
		}
		if len(domain) < 4 || len(domain) > 255 {
			continue
		}
		metadata := map[string]string{"domain": domain}
		add(full, "seer.email_address", "Email address discovered", findings.SeverityLow, metadata)
	}

	sort.SliceStable(detections, func(i, j int) bool {
		if detections[i].kind == detections[j].kind {
			return detections[i].match < detections[j].match
		}
		return detections[i].kind < detections[j].kind
	})

	findingsList := make([]findings.Finding, 0, len(detections))
	for _, det := range detections {
		findingsList = append(findingsList, findings.Finding{
			Version:    findings.SchemaVersion,
			ID:         findings.NewID(),
			Plugin:     "seer",
			Type:       det.kind,
			Message:    det.message,
			Target:     target,
			Evidence:   det.metadata["redacted_match"],
			Severity:   det.severity,
			DetectedAt: findings.NewTimestamp(nowFn()),
			Metadata:   det.metadata,
		})
	}

	return findingsList
}

type allowlist struct {
	exact         map[string]struct{}
	exactLower    map[string]struct{}
	patterns      map[string]struct{}
	patternsLower map[string]struct{}
	domains       map[string]struct{}
	urls          map[string]struct{}
	urlsLower     map[string]struct{}
	paths         map[string]struct{}
}

func buildAllowlist(entries []string) *allowlist {
	if len(entries) == 0 {
		return nil
	}

	al := &allowlist{
		exact:         make(map[string]struct{}),
		exactLower:    make(map[string]struct{}),
		patterns:      make(map[string]struct{}),
		patternsLower: make(map[string]struct{}),
		domains:       make(map[string]struct{}),
		urls:          make(map[string]struct{}),
		urlsLower:     make(map[string]struct{}),
		paths:         make(map[string]struct{}),
	}

	for _, entry := range entries {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}

		lower := strings.ToLower(trimmed)
		switch {
		case strings.HasPrefix(lower, "pattern:"):
			pattern := strings.TrimSpace(trimmed[len("pattern:"):])
			if pattern == "" {
				continue
			}
			al.patterns[pattern] = struct{}{}
			al.patternsLower[strings.ToLower(pattern)] = struct{}{}
		case strings.HasPrefix(lower, "domain:"):
			domain := normalizeDomain(trimmed[len("domain:"):])
			if domain == "" {
				continue
			}
			al.domains[domain] = struct{}{}
		case strings.HasPrefix(lower, "url:"):
			urlVal := strings.TrimSpace(trimmed[len("url:"):])
			if urlVal == "" {
				continue
			}
			al.urls[urlVal] = struct{}{}
			al.urlsLower[strings.ToLower(urlVal)] = struct{}{}
		case strings.HasPrefix(trimmed, "@"):
			domain := normalizeDomain(trimmed[1:])
			if domain == "" {
				continue
			}
			al.domains[domain] = struct{}{}
		case strings.HasPrefix(lower, "path:"):
			rawPath := strings.TrimSpace(trimmed[len("path:"):])
			if rawPath == "" {
				continue
			}
			path := normalizePath(rawPath)
			if path == "" {
				continue
			}
			al.paths[path] = struct{}{}
		case strings.HasPrefix(trimmed, "/"):
			path := normalizePath(trimmed)
			if path == "" {
				continue
			}
			al.paths[path] = struct{}{}
		case strings.Contains(trimmed, "://"):
			al.urls[trimmed] = struct{}{}
			al.urlsLower[strings.ToLower(trimmed)] = struct{}{}
		default:
			al.exact[trimmed] = struct{}{}
			al.exactLower[lower] = struct{}{}
		}
	}

	if len(al.exact) == 0 {
		al.exact = nil
	}
	if len(al.exactLower) == 0 {
		al.exactLower = nil
	}
	if len(al.patterns) == 0 {
		al.patterns = nil
		al.patternsLower = nil
	}
	if len(al.domains) == 0 {
		al.domains = nil
	}
	if len(al.urls) == 0 {
		al.urls = nil
		al.urlsLower = nil
	}
	if len(al.paths) == 0 {
		al.paths = nil
	}

	if al.exact == nil && al.patterns == nil && al.domains == nil && al.urls == nil && al.paths == nil {
		return nil
	}

	return al
}

func shouldAllow(match, kind, target string, metadata map[string]string, allow *allowlist) bool {
	if allow == nil {
		return false
	}

	if allow.patterns != nil {
		if _, ok := allow.patterns[kind]; ok {
			return true
		}
	}
	if allow.patternsLower != nil {
		if _, ok := allow.patternsLower[strings.ToLower(kind)]; ok {
			return true
		}
	}

	if allow.exact != nil {
		if _, ok := allow.exact[match]; ok {
			return true
		}
	}
	if allow.exactLower != nil {
		if _, ok := allow.exactLower[strings.ToLower(match)]; ok {
			return true
		}
	}

	if target != "" {
		if allow.urls != nil {
			if _, ok := allow.urls[target]; ok {
				return true
			}
		}
		if allow.urlsLower != nil {
			if _, ok := allow.urlsLower[strings.ToLower(target)]; ok {
				return true
			}
		}
		if allow.paths != nil {
			if parsed, err := url.Parse(target); err == nil {
				path := normalizePath(parsed.Path)
				if _, ok := allow.paths[path]; ok {
					return true
				}
			}
		}
	}

	if allow.domains != nil {
		domain := strings.ToLower(metadataValue(metadata, "domain"))
		if domain == "" {
			if idx := strings.LastIndex(match, "@"); idx != -1 && idx < len(match)-1 {
				domain = strings.ToLower(match[idx+1:])
			}
		}
		if domain != "" {
			for allowed := range allow.domains {
				if domain == allowed || strings.HasSuffix(domain, "."+allowed) {
					return true
				}
			}
		}
	}

	return false
}

func clampToValidUTF8(content string, maxBytes int) string {
	if !utf8.ValidString(content) {
		for len(content) > 0 && !utf8.ValidString(content) {
			content = content[:len(content)-1]
		}
	}
	if maxBytes <= 0 || len(content) <= maxBytes {
		return content
	}
	trimmed := content[:maxBytes]
	for len(trimmed) > 0 && !utf8.ValidString(trimmed) {
		trimmed = trimmed[:len(trimmed)-1]
	}
	return trimmed
}

func looksBinary(content string) bool {
	if content == "" {
		return false
	}
	runes := []rune(content)
	sample := runes
	if len(sample) > 2048 {
		sample = sample[:2048]
	}
	var nonText int
	for _, r := range sample {
		if r == 0 {
			return true
		}
		if r < 0x20 {
			switch r {
			case '\n', '\r', '\t':
				continue
			default:
				nonText++
			}
			continue
		}
		if !unicode.IsGraphic(r) && !unicode.IsSpace(r) {
			nonText++
		}
	}
	ratio := float64(nonText) / float64(len(sample))
	return ratio > 0.3
}

func parseJWT(token string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}

	header, err := decodeJWTPart(parts[0])
	if err != nil {
		return "", false
	}
	if len(header) == 0 {
		return "", false
	}

	payload, err := decodeJWTPart(parts[1])
	if err != nil {
		return "", false
	}
	if len(payload) == 0 {
		return "", false
	}

	if _, err := decodeJWTPart(parts[2]); err != nil {
		return "", false
	}

	var headerMap map[string]any
	if err := json.Unmarshal(header, &headerMap); err != nil {
		return "", false
	}

	var payloadMap map[string]any
	if err := json.Unmarshal(payload, &payloadMap); err != nil {
		return "", false
	}

	alg, _ := headerMap["alg"].(string)
	return alg, true
}

func decodeJWTPart(segment string) ([]byte, error) {
	if segment == "" {
		return nil, fmt.Errorf("empty segment")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func redact(value string, prefix, suffix int) string {
	if value == "" {
		return ""
	}
	if strings.Contains(value, "@") {
		return redactEmail(value, prefix, suffix)
	}
	return redactGeneral(value, prefix, suffix)
}

func redactGeneral(value string, prefix, suffix int) string {
	runes := []rune(value)
	length := len(runes)
	if length == 0 {
		return ""
	}
	if prefix+suffix >= length {
		return value
	}
	start := runes[:min(prefix, length)]
	end := runes[length-min(suffix, length):]
	return string(start) + "…" + string(end)
}

func redactEmail(value string, prefix, suffix int) string {
	parts := strings.SplitN(value, "@", 2)
	if len(parts) != 2 {
		return redactGeneral(value, prefix, suffix)
	}
	localRunes := []rune(parts[0])
	domainRunes := []rune(parts[1])
	if len(domainRunes) == 0 {
		return redactGeneral(value, prefix, suffix)
	}

	startCount := min(prefix, len(localRunes))
	endCount := min(suffix, len(domainRunes))

	start := string(localRunes[:startCount])
	var localEllipsis string
	if startCount < len(localRunes) {
		localEllipsis = "…"
	}

	var domainSegment string
	switch {
	case endCount >= len(domainRunes):
		domainSegment = string(domainRunes)
	case endCount <= 0:
		domainSegment = "…"
	default:
		domainSegment = "…" + string(domainRunes[len(domainRunes)-endCount:])
	}

	if localEllipsis == "" && domainSegment == string(domainRunes) {
		return value
	}

	return start + localEllipsis + "@" + domainSegment
}

func metadataValue(meta map[string]string, key string) string {
	if meta == nil {
		return ""
	}
	return meta[key]
}

func normalizeDomain(value string) string {
	domain := strings.TrimSpace(value)
	domain = strings.Trim(domain, " .")
	domain = strings.TrimPrefix(domain, "@")
	domain = strings.ToLower(domain)
	if domain == "" {
		return ""
	}
	if !strings.Contains(domain, ".") {
		return ""
	}
	return domain
}

func normalizePath(value string) string {
	path := strings.TrimSpace(value)
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func shannonEntropy(input string) float64 {
	runes := []rune(input)
	if len(runes) == 0 {
		return 0
	}
	counts := make(map[rune]int, len(runes))
	for _, r := range runes {
		counts[r]++
	}
	total := float64(len(runes))
	var entropy float64
	for _, count := range counts {
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}
