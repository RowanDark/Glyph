# Seer

Seer inspects passive telemetry to spot anomalies and suspicious behaviors before they escalate into incidents. The v0.3 release focuses on low-noise secret and PII detection tailored for HTTP response bodies.

## Capabilities
- `CAP_HTTP_PASSIVE`
- `CAP_EMIT_FINDINGS`

## Detection coverage
The detector library in [`internal/seer`](../../internal/seer) powers the plugin. It combines tuned regular expressions with Shannon entropy heuristics and emits structured findings when it observes:

- AWS access key identifiers (e.g. `AKIA...`).
- Slack tokens (`xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-`).
- High-entropy generic API keys surfaced through common `api_key=`, `token=`, or `secret=` patterns.
- Google API keys beginning with `AIza` that also satisfy entropy requirements.
- JSON Web Tokens (JWTs) that contain valid base64url-encoded header and payload segments.
- Email addresses to aid triage. Evidence is redacted to the first and last character of the local-part (for example `alerts@example.com` is reported as `a****s@example.com`).

Evidence for tokens is redacted to only retain the last four characters (e.g. `AKIAABCDEFGHIJKLMNOP` becomes `****************MNOP`). This keeps operator tooling actionable without leaking the full secret. Never store real credentials in fixtures or logs—synthetic examples keep the training corpus safe.

## Defaults and thresholds

- **Entropy floors.** Generic API keys and Google API keys must exceed an entropy threshold of **3.5 bits per byte**, while JWTs require at least **3.0**. The detector records both the observed entropy and the enforced floor in finding metadata so analysts can see why a string qualified.
- **Evidence redaction.** Evidence is redacted by default to preserve the first **four** and last **four** characters. Override the prefix/suffix via `SEER_EVIDENCE_PREFIX` and `SEER_EVIDENCE_SUFFIX` or the corresponding CLI flags when tighter masking is required. Email addresses retain their domain suffix while the local-part collapses to a prefix plus ellipsis.
- **Binary avoidance.** The scanner skips binary payloads using content-type hints and printable character ratios before attempting pattern matches, preventing noisy findings from images or archives.
- Email addresses preserve their domain suffix and only reveal the configured prefix of the local-part. Seer emits an ellipsis (`…`) to denote redacted segments.

These defaults can be tuned per deployment, but the shipped values balance fidelity with safe disclosure for most environments.

## Configuration
The binary accepts the following flags (defaults can also be provided through environment variables):

| Flag | Environment | Description |
| ---- | ----------- | ----------- |
| `--server` | `GLYPH_SERVER` | glyphd gRPC address (defaults to `127.0.0.1:50051`). |
| `--token` | `GLYPH_AUTH_TOKEN` | Authentication token for glyphd (defaults to `supersecrettoken`). |
| `--allowlist` | `SEER_ALLOWLIST_FILE` | Optional path to a newline-separated allowlist file. Lines starting with `#` are treated as comments. |

In addition, `SEER_ALLOWLIST` can supply a comma-separated list of allowlisted tokens or email addresses. All allowlist sources are merged, deduplicated case-insensitively, and applied before any findings are emitted. The plugin also skips binary payloads based on response metadata and byte heuristics to reduce noise from non-text artifacts.

### Allowlisting corporate domains

Create an allowlist file when traffic legitimately contains internal identities. Prefix entries with `domain:` (or use the shorthand `@example.corp`) to permit entire domains while keeping other detections active:

```
# seer-allowlist.txt
domain:corp.example
```

Run Seer with `--allowlist seer-allowlist.txt` (or set `SEER_ALLOWLIST_FILE`) to suppress alerting on corporate email loops while leaving third-party domains and token detections untouched. Combine file-based entries with the `SEER_ALLOWLIST` environment variable for one-off redactions without editing the shared policy.

## Safety
Fixtures and documentation only contain fake credential shapes. Do not record genuine secrets in tests or repositories—always use synthetic values when exercising the detectors.
