#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    backtrace::Backtrace,
    cmp::Ordering,
    collections::{BTreeMap, HashMap},
    convert::TryFrom,
    fs,
    io::{BufRead, BufReader, Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
    sync::Mutex,
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD as Base64Engine, Engine as _};
use chrono::{DateTime, NaiveDateTime, SecondsFormat, Utc};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use futures::{
    future::{AbortHandle, Abortable},
    StreamExt,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{from_str, json, Value};
use sha2::{Digest, Sha256};
use tar::{Archive, Builder, Header};
use tauri::{async_runtime, Manager, State, Window};
use tempfile::TempDir;
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
enum ApiError {
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("unexpected response ({status}): {body}")]
    UnexpectedResponse { status: StatusCode, body: String },
    #[error("window not available")]
    WindowMissing,
}

#[derive(Clone)]
struct StreamController {
    abort: AbortHandle,
}

impl StreamController {
    fn stop(self) {
        self.abort.abort();
    }
}

fn build_stream_key(prefix: &str, id: &str) -> String {
    format!("{prefix}:{id}")
}

struct GlyphApi {
    client: reqwest::Client,
    base_url: String,
    streams: Mutex<HashMap<String, StreamController>>,
}

impl GlyphApi {
    fn new() -> Self {
        let base_url =
            std::env::var("GLYPH_API_URL").unwrap_or_else(|_| "http://127.0.0.1:8713".to_string());
        let parsed = Url::parse(&base_url).expect("invalid GLYPH_API_URL");
        match parsed.host_str() {
            Some("127.0.0.1") | Some("localhost") | Some("::1") => {}
            other => panic!("GLYPH_API_URL must point to localhost, got {:?}", other),
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client");

        Self {
            client,
            base_url,
            streams: Mutex::new(HashMap::new()),
        }
    }

    fn endpoint(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }
}

struct CrashReportState {
    current: Mutex<Option<CrashBundle>>,
}

impl CrashReportState {
    fn new() -> Self {
        Self {
            current: Mutex::new(None),
        }
    }
}

#[derive(Clone)]
struct CrashBundle {
    generated_at: DateTime<Utc>,
    files: Vec<CrashFile>,
    warnings: Vec<String>,
}

#[derive(Clone)]
struct CrashFile {
    name: String,
    description: String,
    content: Vec<u8>,
    redacted: bool,
    sha256: String,
}

impl CrashFile {
    fn new(name: &str, description: &str, content: Vec<u8>, redacted: bool) -> Self {
        let sha256 = compute_sha256(&content);
        Self {
            name: name.to_string(),
            description: description.to_string(),
            content,
            redacted,
            sha256,
        }
    }

    fn size(&self) -> usize {
        self.content.len()
    }
}

impl CrashBundle {
    fn preview(&self) -> CrashReportPreview {
        let files = self
            .files
            .iter()
            .map(|file| CrashFilePreview {
                name: file.name.clone(),
                description: file.description.clone(),
                size: file.size(),
                sha256: file.sha256.clone(),
                redacted: file.redacted,
                snippet: snippet_from(&file.content),
            })
            .collect();
        CrashReportPreview {
            generated_at: self
                .generated_at
                .to_rfc3339_opts(SecondsFormat::Millis, true),
            files,
            warnings: self.warnings.clone(),
        }
    }

    fn manifest(&self) -> CrashManifest {
        let files = self
            .files
            .iter()
            .map(|file| CrashManifestFile {
                name: &file.name,
                description: &file.description,
                size: file.size(),
                sha256: &file.sha256,
                redacted: file.redacted,
            })
            .collect();
        CrashManifest {
            generated_at: self
                .generated_at
                .to_rfc3339_opts(SecondsFormat::Millis, true),
            warnings: &self.warnings,
            files,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CrashFilePreview {
    name: String,
    description: String,
    size: usize,
    sha256: String,
    redacted: bool,
    snippet: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CrashReportPreview {
    generated_at: String,
    files: Vec<CrashFilePreview>,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CrashManifest<'a> {
    generated_at: String,
    warnings: &'a [String],
    files: Vec<CrashManifestFile<'a>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CrashManifestFile<'a> {
    name: &'a str,
    description: &'a str,
    size: usize,
    sha256: &'a str,
    redacted: bool,
}

const MAX_LOG_BYTES: u64 = 512 * 1024;
const STACK_FILE_NAME: &str = "stackdump.txt";
const METRICS_FILE_NAME: &str = "metrics.prom";
const AUDIT_LOG_FILE_NAME: &str = "audit-log.jsonl";
const SENSITIVE_KEYS: &[&str] = &[
    "authorization",
    "token",
    "secret",
    "password",
    "api_key",
    "apikey",
    "access_token",
];

fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

fn snippet_from(data: &[u8]) -> String {
    const LIMIT: usize = 2048;
    if data.is_empty() {
        return String::new();
    }
    let slice = if data.len() > LIMIT {
        &data[..LIMIT]
    } else {
        data
    };
    let mut snippet = String::from_utf8_lossy(slice).to_string();
    if data.len() > LIMIT {
        snippet.push_str("\n… (truncated)");
    }
    snippet
}

fn sanitize_entry_name(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return "file".to_string();
    }
    let mut result = String::with_capacity(trimmed.len());
    for ch in trimmed.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
            result.push(ch);
        } else {
            result.push('_');
        }
    }
    if result.is_empty() {
        "file".to_string()
    } else {
        result
    }
}

fn should_redact_key(key: &str) -> bool {
    let mut lowered = key.to_ascii_lowercase();
    lowered.retain(|ch| ch != '_' && ch != '-' && ch != '.');
    SENSITIVE_KEYS
        .iter()
        .any(|candidate| *candidate == lowered || *candidate == key)
}

fn redact_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in keys {
                if let Some(entry) = map.get_mut(&key) {
                    if should_redact_key(&key) {
                        *entry = Value::String("[REDACTED]".to_string());
                    } else {
                        redact_value(entry);
                    }
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_value(item);
            }
        }
        Value::String(text) => {
            if text.len() > 128 {
                *text = "[REDACTED]".to_string();
            }
        }
        _ => {}
    }
}

fn redact_audit_log(data: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(data.len());
    for line in data.split(|b| *b == b'\n') {
        if line.is_empty() {
            output.push(b'\n');
            continue;
        }
        match serde_json::from_slice::<Value>(line) {
            Ok(mut value) => {
                redact_value(&mut value);
                match serde_json::to_vec(&value) {
                    Ok(mut encoded) => {
                        output.append(&mut encoded);
                        output.push(b'\n');
                    }
                    Err(_) => {
                        output.extend_from_slice(line);
                        output.push(b'\n');
                    }
                }
            }
            Err(_) => {
                output.extend_from_slice(line);
                output.push(b'\n');
            }
        }
    }
    output
}

fn read_recent_file(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let mut file = fs::File::open(path).map_err(|err| format!("open {path:?}: {err}"))?;
    let metadata = file
        .metadata()
        .map_err(|err| format!("stat {path:?}: {err}"))?;
    let truncated = metadata.len() > limit;
    let mut buffer = Vec::new();
    if truncated {
        let offset = i64::try_from(limit).unwrap_or(i64::MAX);
        file.seek(SeekFrom::End(-offset))
            .map_err(|err| format!("seek {path:?}: {err}"))?;
    }
    file.read_to_end(&mut buffer)
        .map_err(|err| format!("read {path:?}: {err}"))?;
    if truncated {
        if let Some(first_newline) = buffer.iter().position(|&byte| byte == b'\n') {
            buffer.drain(..=first_newline);
        } else {
            buffer.clear();
        }
    }
    Ok(buffer)
}

fn bundle_mtime(bundle: &CrashBundle) -> u64 {
    bundle.generated_at.timestamp().max(0) as u64
}

fn capture_stack_trace() -> CrashFile {
    let header = format!(
        "Glyph desktop shell diagnostic stack\nGenerated at: {}\n\n",
        Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
    );
    let trace = Backtrace::force_capture();
    let mut payload = header.into_bytes();
    payload.extend_from_slice(trace.to_string().as_bytes());
    CrashFile::new(
        STACK_FILE_NAME,
        "Stack trace for the desktop shell process",
        payload,
        false,
    )
}

fn capture_audit_log(path: &Path) -> Result<Option<CrashFile>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let recent = read_recent_file(path, MAX_LOG_BYTES)?;
    let sanitized = redact_audit_log(&recent);
    Ok(Some(CrashFile::new(
        AUDIT_LOG_FILE_NAME,
        "Recent Glyph audit log entries (redacted)",
        sanitized,
        true,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn read_recent_file_discards_partial_first_line_when_truncated() {
        let mut file = NamedTempFile::new().expect("create temp file");
        write!(file, "line1\nline2\nline3\n").expect("write log contents");

        let data = read_recent_file(file.path(), 10).expect("read truncated log");

        assert_eq!(String::from_utf8(data).unwrap(), "line3\n");
    }

    #[test]
    fn read_recent_file_returns_full_contents_when_not_truncated() {
        let mut file = NamedTempFile::new().expect("create temp file");
        write!(file, "line1\nline2\n").expect("write log contents");

        let data = read_recent_file(file.path(), 1024).expect("read full log");

        assert_eq!(String::from_utf8(data).unwrap(), "line1\nline2\n");
    }
}

async fn capture_metrics(api: &GlyphApi) -> Result<CrashFile, String> {
    let url = api.endpoint("metrics");
    let response = api
        .client
        .get(url)
        .send()
        .await
        .map_err(|err| format!("request metrics: {err}"))?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(ApiError::UnexpectedResponse { status, body }.to_string());
    }
    let body = response
        .text()
        .await
        .map_err(|err| format!("read metrics body: {err}"))?;
    Ok(CrashFile::new(
        METRICS_FILE_NAME,
        "Snapshot of Glyph metrics endpoint",
        body.into_bytes(),
        false,
    ))
}

#[tauri::command]
async fn prepare_crash_report(
    api: State<'_, GlyphApi>,
    crash: State<'_, CrashReportState>,
) -> Result<CrashReportPreview, String> {
    let mut files = Vec::new();
    let mut warnings = Vec::new();

    files.push(capture_stack_trace());

    match std::env::var("GLYPH_AUDIT_LOG_PATH") {
        Ok(path) if !path.trim().is_empty() => {
            let path_buf = PathBuf::from(path.trim());
            match capture_audit_log(&path_buf) {
                Ok(Some(file)) => files.push(file),
                Ok(None) => warnings.push(format!(
                    "No audit log entries found at {}.",
                    path_buf.display()
                )),
                Err(err) => warnings.push(format!("Failed to read audit log: {err}")),
            }
        }
        _ => warnings.push(
            "GLYPH_AUDIT_LOG_PATH is not configured; audit log will not be included.".to_string(),
        ),
    }

    match capture_metrics(&api).await {
        Ok(file) => files.push(file),
        Err(err) => warnings.push(format!("Failed to capture metrics: {err}")),
    }

    let bundle = CrashBundle {
        generated_at: Utc::now(),
        files,
        warnings,
    };
    let preview = bundle.preview();

    {
        let mut guard = crash.current.lock().map_err(|err| err.to_string())?;
        *guard = Some(bundle);
    }

    Ok(preview)
}

#[tauri::command]
async fn save_crash_report(path: String, crash: State<'_, CrashReportState>) -> Result<(), String> {
    let destination = path.trim();
    if destination.is_empty() {
        return Err("Destination path is required".to_string());
    }
    let bundle = {
        let guard = crash.current.lock().map_err(|err| err.to_string())?;
        guard
            .clone()
            .ok_or_else(|| "No crash report prepared yet".to_string())?
    };
    write_crash_bundle(&bundle, destination)
}

fn write_crash_bundle(bundle: &CrashBundle, destination: &str) -> Result<(), String> {
    let file =
        fs::File::create(destination).map_err(|err| format!("create {destination:?}: {err}"))?;
    let mut encoder = GzEncoder::new(file, Compression::default());
    {
        let mut builder = Builder::new(&mut encoder);
        let manifest = bundle.manifest();
        let manifest_data = serde_json::to_vec_pretty(&manifest)
            .map_err(|err| format!("encode manifest: {err}"))?;
        let mut header = Header::new_gnu();
        header.set_size(manifest_data.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(bundle_mtime(bundle));
        header.set_cksum();
        builder
            .append_data(&mut header, "manifest.json", manifest_data.as_slice())
            .map_err(|err| format!("write manifest: {err}"))?;

        for file in &bundle.files {
            let entry_name = sanitize_entry_name(&file.name);
            let path = format!("files/{entry_name}");
            let mut header = Header::new_gnu();
            header.set_size(file.size() as u64);
            header.set_mode(0o644);
            header.set_mtime(bundle_mtime(bundle));
            header.set_cksum();
            builder
                .append_data(&mut header, path, file.content.as_slice())
                .map_err(|err| format!("write bundle file {}: {err}", file.name))?;
        }

        builder
            .finish()
            .map_err(|err| format!("finalise bundle: {err}"))?;
    }
    encoder
        .finish()
        .map_err(|err| format!("finalise compression: {err}"))?;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Run {
    id: String,
    name: String,
    status: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RunLimits {
    concurrency: u32,
    max_rps: u32,
    max_findings: u32,
    safe_mode: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RunAuth {
    strategy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    api_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oauth_client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oauth_client_secret: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RunSchedule {
    mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timezone: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartRunRequest {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    template: Option<String>,
    targets: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_notes: Option<String>,
    scope_policy: String,
    plugins: Vec<String>,
    limits: RunLimits,
    auth: RunAuth,
    schedule: RunSchedule,
}

#[derive(Debug, Serialize, Deserialize)]
struct StartRunResponse {
    id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct RunEvent {
    #[serde(rename = "type")]
    kind: String,
    timestamp: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    payload: Value,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct LatencyBucket {
    upper_bound_ms: f64,
    count: f64,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct PluginErrorTotal {
    plugin: String,
    errors: f64,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct DashboardMetrics {
    failures: f64,
    queue_depth: f64,
    avg_latency_ms: f64,
    cases_found: f64,
    events_total: f64,
    queue_drops: f64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    latency_buckets: Vec<LatencyBucket>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    plugin_errors: Vec<PluginErrorTotal>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct FlowEventPayload {
    id: String,
    sequence: u64,
    #[serde(rename = "type")]
    kind: String,
    timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sanitized: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sanitized_base64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_base64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_body_size: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_body_captured: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sanitized_redacted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plugin_tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FlowPage {
    items: Vec<FlowEventPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
struct FlowFilters {
    #[serde(skip_serializing_if = "Option::is_none")]
    search: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    statuses: Vec<i32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    scope: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    plugin_tags: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResendFlowResponse {
    flow_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScopePolicyDocument {
    policy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default, alias = "updated_at")]
    updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ScopeValidationMessage {
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    column: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScopeValidationResult {
    valid: bool,
    #[serde(default)]
    errors: Vec<ScopeValidationMessage>,
    #[serde(default)]
    warnings: Vec<ScopeValidationMessage>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScopeApplyResponse {
    policy: String,
    applied_at: DateTime<Utc>,
    #[serde(default)]
    warnings: Vec<ScopeValidationMessage>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ScopeRule {
    #[serde(rename = "type")]
    kind: String,
    value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
struct ScopeRuleSet {
    #[serde(default)]
    allow: Vec<ScopeRule>,
    #[serde(default)]
    deny: Vec<ScopeRule>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScopeParseSuggestion {
    policy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rules: Option<ScopeRuleSet>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScopeParseResponse {
    #[serde(default)]
    suggestions: Vec<ScopeParseSuggestion>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScopeDryRunDecision {
    url: String,
    allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    matched_rule: Option<ScopeRule>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScopeDryRunResponse {
    #[serde(default)]
    results: Vec<ScopeDryRunDecision>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    version: String,
    created_at: DateTime<Utc>,
    #[serde(default)]
    seeds: HashMap<String, i64>,
    #[serde(default)]
    dns: Vec<ManifestDnsRecord>,
    #[serde(default)]
    tls: Vec<ManifestTlsRecord>,
    #[serde(default)]
    robots: Vec<ManifestRobotsRecord>,
    #[serde(default)]
    rate_limits: Vec<ManifestRateLimitRecord>,
    #[serde(default)]
    cookies: Vec<ManifestCookieRecord>,
    #[serde(default)]
    responses: Vec<ManifestResponseRecord>,
    #[serde(default)]
    flows_file: Option<String>,
    runner: ManifestRunnerInfo,
    #[serde(default)]
    plugins: Vec<ManifestPluginInfo>,
    findings_file: String,
    cases_file: String,
    case_timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ManifestDnsRecord {
    host: String,
    #[serde(default)]
    addresses: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ManifestTlsRecord {
    host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ja3: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ja3_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    negotiated_alpn: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    offered_alpn: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ManifestRobotsRecord {
    host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    body_file: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ManifestRateLimitRecord {
    host: String,
    policy: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ManifestCookieRecord {
    domain: String,
    name: String,
    value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ManifestResponseRecord {
    request_url: String,
    method: String,
    status: i32,
    #[serde(default)]
    headers: HashMap<String, Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body_file: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ManifestRunnerInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    glyphctl_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    glyphd_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    go_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    arch: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ManifestPluginInfo {
    name: String,
    version: String,
    manifest_path: String,
    signature: String,
    sha256: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CaseRecord {
    version: String,
    id: String,
    asset: CaseAsset,
    vector: CaseAttackVector,
    summary: String,
    #[serde(default)]
    evidence: Vec<CaseEvidenceItem>,
    proof: CaseProof,
    risk: CaseRisk,
    confidence: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    confidence_log: Option<String>,
    #[serde(default)]
    sources: Vec<CaseSourceFinding>,
    generated_at: String,
    #[serde(default)]
    labels: HashMap<String, String>,
    graph: CaseExploitGraph,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CaseAsset {
    kind: String,
    identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CaseAttackVector {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CaseEvidenceItem {
    plugin: String,
    #[serde(rename = "type")]
    kind: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: Option<String>,
    #[serde(default)]
    metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CaseProof {
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,
    #[serde(default)]
    steps: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CaseRisk {
    severity: String,
    score: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    rationale: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CaseSourceFinding {
    id: String,
    plugin: String,
    #[serde(rename = "type")]
    kind: String,
    severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CaseExploitGraph {
    dot: String,
    mermaid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,
    #[serde(default)]
    attack_path: Vec<CaseChainStep>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CaseChainStep {
    stage: i32,
    from: String,
    to: String,
    description: String,
    plugin: String,
    #[serde(rename = "type")]
    kind: String,
    finding_id: String,
    severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    weak_link: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct ReplayFlowRecord {
    id: String,
    sequence: u64,
    #[serde(rename = "type")]
    kind: String,
    timestamp_unix: i64,
    #[serde(default)]
    sanitized_base64: Option<String>,
    #[serde(default)]
    raw_body_bytes: Option<i64>,
    #[serde(default)]
    raw_body_captured: Option<i64>,
    #[serde(default)]
    sanitized_redacted: Option<bool>,
}

struct ReplayDataset {
    _temp_dir: TempDir,
    manifest: Manifest,
    cases: Vec<CaseRecord>,
    flows: Vec<FlowEventPayload>,
    metrics: DashboardMetrics,
}

struct ReplayState {
    current: Mutex<Option<ReplayDataset>>,
}

impl ReplayState {
    fn new() -> Self {
        Self {
            current: Mutex::new(None),
        }
    }
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct OpenArtifactResponse {
    manifest: Manifest,
    metrics: DashboardMetrics,
    case_count: usize,
    flow_count: usize,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ArtifactStatus {
    loaded: bool,
    manifest: Option<Manifest>,
    metrics: Option<DashboardMetrics>,
    case_count: usize,
    flow_count: usize,
}

#[derive(Debug)]
struct MetricSample {
    name: String,
    labels: HashMap<String, String>,
    value: f64,
}

fn parse_metric_identifier(identifier: &str) -> Option<(String, HashMap<String, String>)> {
    if let Some(start) = identifier.find('{') {
        let end = identifier.rfind('}')?;
        let name = identifier[..start].to_string();
        let mut labels = HashMap::new();
        let inner = &identifier[start + 1..end];
        for pair in inner.split(',') {
            let trimmed = pair.trim();
            if trimmed.is_empty() {
                continue;
            }
            let mut parts = trimmed.splitn(2, '=');
            let key = parts.next()?.trim();
            let raw_value = parts.next()?.trim();
            let value = raw_value
                .trim_matches('"')
                .replace("\\\"", "\"")
                .replace("\\\\", "\\");
            labels.insert(key.to_string(), value);
        }
        Some((name, labels))
    } else {
        Some((identifier.to_string(), HashMap::new()))
    }
}

fn parse_metric_line(line: &str) -> Option<MetricSample> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let mut parts = trimmed.split_whitespace();
    let metric_part = parts.next()?;
    let value_str = parts.next()?;
    // Ignore optional timestamp token if present.
    let _timestamp = parts.next();
    let value: f64 = value_str.parse().ok()?;
    let (name, labels) = parse_metric_identifier(metric_part)?;

    Some(MetricSample {
        name,
        labels,
        value,
    })
}

fn parse_metrics(body: &str) -> Vec<MetricSample> {
    body.lines().filter_map(parse_metric_line).collect()
}

fn sum_metric(samples: &[MetricSample], name: &str) -> f64 {
    samples
        .iter()
        .filter(|sample| sample.name == name)
        .map(|sample| sample.value)
        .sum()
}

fn sum_metric_by_label(samples: &[MetricSample], name: &str, label: &str) -> HashMap<String, f64> {
    let mut totals = HashMap::new();
    for sample in samples.iter().filter(|sample| sample.name == name) {
        if let Some(value) = sample.labels.get(label) {
            *totals.entry(value.clone()).or_insert(0.0) += sample.value;
        }
    }
    totals
}

fn sum_metric_by_label_any(
    samples: &[MetricSample],
    names: &[&str],
    label: &str,
) -> HashMap<String, f64> {
    let mut totals = HashMap::new();
    for name in names {
        for (key, value) in sum_metric_by_label(samples, name, label) {
            *totals.entry(key).or_insert(0.0) += value;
        }
    }
    totals
}

fn collect_latency_buckets(samples: &[MetricSample], name: &str) -> Vec<LatencyBucket> {
    let mut buckets: BTreeMap<f64, f64> = BTreeMap::new();
    for sample in samples.iter().filter(|sample| sample.name == name) {
        if let Some(bound_str) = sample.labels.get("le") {
            if bound_str == "+Inf" {
                continue;
            }
            if let Ok(bound) = bound_str.parse::<f64>() {
                let key = (bound * 1000.0).max(0.0);
                *buckets.entry(key).or_insert(0.0) += sample.value;
            }
        }
    }

    buckets
        .into_iter()
        .map(|(upper_bound_ms, count)| LatencyBucket {
            upper_bound_ms,
            count,
        })
        .collect()
}

fn unix_to_datetime(secs: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(secs, 0).unwrap_or_else(|| {
        let fallback = NaiveDateTime::from_timestamp_opt(0, 0).unwrap();
        DateTime::<Utc>::from_utc(fallback, Utc)
    })
}

fn decode_base64_to_string(value: &str) -> Option<String> {
    Base64Engine
        .decode(value)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

fn is_safe_entry_path(path: &Path) -> bool {
    let mut components = path.components();
    match components.clone().next() {
        Some(Component::Prefix(_)) | Some(Component::RootDir) => return false,
        _ => {}
    }
    components.all(|component| !matches!(component, Component::ParentDir))
}

fn extract_artifact(source: &Path, dest: &Path) -> Result<Manifest, String> {
    if source.as_os_str().is_empty() {
        return Err("artifact path is required".to_string());
    }
    if dest.as_os_str().is_empty() {
        return Err("destination path is required".to_string());
    }
    fs::create_dir_all(dest).map_err(|err| format!("create destination: {err}"))?;

    let file = fs::File::open(source).map_err(|err| format!("open artifact: {err}"))?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);

    let entries = archive
        .entries()
        .map_err(|err| format!("read artifact entries: {err}"))?;

    for entry in entries {
        let mut entry = entry.map_err(|err| format!("read tar entry: {err}"))?;
        let path = entry
            .path()
            .map_err(|err| format!("resolve entry path: {err}"))?
            .to_path_buf();
        if !is_safe_entry_path(&path) {
            return Err(format!("entry {:?} has unsafe path", path));
        }
        let target = dest.join(&path);
        if !target.starts_with(dest) {
            return Err(format!("entry {:?} escapes destination", path));
        }
        entry
            .unpack(&target)
            .map_err(|err| format!("extract entry {:?}: {err}", path))?;
    }

    let manifest_path = dest.join("manifest.json");
    let data = fs::read(&manifest_path).map_err(|err| format!("read manifest: {err}"))?;
    let manifest: Manifest =
        serde_json::from_slice(&data).map_err(|err| format!("decode manifest: {err}"))?;
    Ok(manifest)
}

fn manifest_child_path(root: &Path, value: &str, field: &str) -> Result<PathBuf, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{field} path is empty"));
    }

    let relative = Path::new(trimmed);
    if !is_safe_entry_path(relative) {
        return Err(format!("{field} path is invalid"));
    }

    let path = root.join(relative);
    if !path.starts_with(root) {
        return Err(format!("{field} path escapes artifact root"));
    }

    Ok(path)
}

fn load_cases(root: &Path, manifest: &Manifest) -> Result<Vec<CaseRecord>, String> {
    let path = manifest_child_path(root, &manifest.cases_file, "cases file")?;
    let data = fs::read(&path).map_err(|err| format!("read cases: {err}"))?;
    let mut cases: Vec<CaseRecord> =
        serde_json::from_slice(&data).map_err(|err| format!("decode cases: {err}"))?;
    cases.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(cases)
}

fn load_flows(root: &Path, manifest: &Manifest) -> Result<Vec<FlowEventPayload>, String> {
    let Some(flow_value) = manifest
        .flows_file
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    else {
        return Ok(Vec::new());
    };

    let path = manifest_child_path(root, flow_value, "flows file")?;
    let file = fs::File::open(&path).map_err(|err| format!("open flows: {err}"))?;
    let reader = BufReader::new(file);
    let mut records = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|err| format!("read flow record: {err}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let record: ReplayFlowRecord =
            serde_json::from_str(&line).map_err(|err| format!("decode flow record: {err}"))?;
        records.push(record);
    }

    records.sort_by(|a, b| {
        if a.sequence == b.sequence {
            a.id.cmp(&b.id)
        } else {
            a.sequence.cmp(&b.sequence)
        }
    });

    let mut events = Vec::with_capacity(records.len());
    for record in records {
        let ReplayFlowRecord {
            id,
            sequence,
            kind,
            timestamp_unix,
            sanitized_base64,
            raw_body_bytes,
            raw_body_captured,
            sanitized_redacted,
        } = record;
        let sanitized_text = sanitized_base64
            .as_ref()
            .and_then(|value| decode_base64_to_string(value));
        events.push(FlowEventPayload {
            id,
            sequence,
            kind,
            timestamp: unix_to_datetime(timestamp_unix),
            sanitized: sanitized_text,
            sanitized_base64,
            raw: None,
            raw_base64: None,
            raw_body_size: raw_body_bytes,
            raw_body_captured,
            sanitized_redacted,
            scope: None,
            tags: None,
            plugin_tags: None,
            metadata: None,
        });
    }

    Ok(events)
}

fn build_artifact_metrics(cases: &[CaseRecord]) -> DashboardMetrics {
    DashboardMetrics {
        failures: 0.0,
        queue_depth: 0.0,
        avg_latency_ms: 0.0,
        cases_found: cases.len() as f64,
        events_total: 0.0,
        queue_drops: 0.0,
        latency_buckets: Vec::new(),
        plugin_errors: Vec::new(),
    }
}

#[tauri::command]
async fn open_artifact(
    replay: State<'_, ReplayState>,
    path: String,
) -> Result<OpenArtifactResponse, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("artifact path is required".to_string());
    }

    let source = PathBuf::from(trimmed);
    let temp_dir = TempDir::new().map_err(|err| format!("create temp dir: {err}"))?;
    let manifest = extract_artifact(&source, temp_dir.path())?;
    let cases = load_cases(temp_dir.path(), &manifest)?;
    let flows = load_flows(temp_dir.path(), &manifest)?;
    let metrics = build_artifact_metrics(&cases);

    let summary = OpenArtifactResponse {
        manifest: manifest.clone(),
        metrics: metrics.clone(),
        case_count: cases.len(),
        flow_count: flows.len(),
    };

    let dataset = ReplayDataset {
        _temp_dir: temp_dir,
        manifest,
        cases,
        flows,
        metrics,
    };

    let mut guard = replay.current.lock().map_err(|err| err.to_string())?;
    *guard = Some(dataset);

    Ok(summary)
}

#[tauri::command]
fn artifact_status(replay: State<'_, ReplayState>) -> Result<ArtifactStatus, String> {
    let guard = replay.current.lock().map_err(|err| err.to_string())?;
    if let Some(dataset) = guard.as_ref() {
        Ok(ArtifactStatus {
            loaded: true,
            manifest: Some(dataset.manifest.clone()),
            metrics: Some(dataset.metrics.clone()),
            case_count: dataset.cases.len(),
            flow_count: dataset.flows.len(),
        })
    } else {
        Ok(ArtifactStatus {
            loaded: false,
            manifest: None,
            metrics: None,
            case_count: 0,
            flow_count: 0,
        })
    }
}

#[tauri::command]
fn list_cases(replay: State<'_, ReplayState>) -> Result<Vec<CaseRecord>, String> {
    let guard = replay.current.lock().map_err(|err| err.to_string())?;
    if let Some(dataset) = guard.as_ref() {
        Ok(dataset.cases.clone())
    } else {
        Err("no artifact loaded".to_string())
    }
}

#[tauri::command]
async fn list_runs(api: State<'_, GlyphApi>) -> Result<Vec<Run>, String> {
    let url = api.endpoint("runs");
    let response = api
        .client
        .get(url)
        .send()
        .await
        .map_err(|err| err.to_string())?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(ApiError::UnexpectedResponse { status, body }.to_string());
    }

    response
        .json::<Vec<Run>>()
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn start_run(
    api: State<'_, GlyphApi>,
    payload: StartRunRequest,
) -> Result<StartRunResponse, String> {
    let url = api.endpoint("runs");
    let response = api
        .client
        .post(url)
        .json(&payload)
        .send()
        .await
        .map_err(|err| err.to_string())?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(ApiError::UnexpectedResponse { status, body }.to_string());
    }

    response
        .json::<StartRunResponse>()
        .await
        .map_err(|err| err.to_string())
}

fn emit_run_event(window: &Window, run_id: &str, event: RunEvent) -> Result<(), ApiError> {
    let event_name = format!("runs:{}:events", run_id);
    window
        .emit(event_name, Some(event))
        .map_err(|_| ApiError::WindowMissing)
}

fn emit_flow_event(
    window: &Window,
    stream_id: &str,
    event: FlowEventPayload,
) -> Result<(), ApiError> {
    let event_name = format!("flows:{}:events", stream_id);
    window
        .emit(event_name, Some(event))
        .map_err(|_| ApiError::WindowMissing)
}

#[tauri::command]
async fn fetch_metrics(
    api: State<'_, GlyphApi>,
    replay: State<'_, ReplayState>,
) -> Result<DashboardMetrics, String> {
    if let Some(metrics) = {
        let guard = replay.current.lock().map_err(|err| err.to_string())?;
        guard.as_ref().map(|dataset| dataset.metrics.clone())
    } {
        return Ok(metrics);
    }

    let url = api.endpoint("metrics");
    let response = api
        .client
        .get(url)
        .send()
        .await
        .map_err(|err| err.to_string())?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(ApiError::UnexpectedResponse { status, body }.to_string());
    }

    let body = response.text().await.map_err(|err| err.to_string())?;
    let samples = parse_metrics(&body);

    let failures = sum_metric(&samples, "glyph_rpc_errors_total");
    let queue_depth = sum_metric(&samples, "glyph_plugin_queue_length");
    let latency_sum = sum_metric(&samples, "glyph_plugin_event_duration_seconds_sum");
    let latency_count = sum_metric(&samples, "glyph_plugin_event_duration_seconds_count");
    let avg_latency_ms = if latency_count > 0.0 {
        (latency_sum / latency_count) * 1000.0
    } else {
        0.0
    };
    let events_total = latency_count;
    let queue_drops = sum_metric(&samples, "glyph_plugin_queue_dropped_total");
    let latency_buckets =
        collect_latency_buckets(&samples, "glyph_plugin_event_duration_seconds_bucket");
    let mut plugin_errors: Vec<PluginErrorTotal> = sum_metric_by_label_any(
        &samples,
        &[
            "glyph_plugin_errors_total",
            "glyph_plugin_event_failures_total",
        ],
        "plugin",
    )
    .into_iter()
    .map(|(plugin, errors)| PluginErrorTotal { plugin, errors })
    .collect();
    plugin_errors.sort_by(|a, b| b.errors.partial_cmp(&a.errors).unwrap_or(Ordering::Equal));

    let mut cases_found = 0.0;
    for name in [
        "glyph_cases_total",
        "glyph_case_reports_total",
        "glyph_case_count",
        "glyph_cases_emitted_total",
        "glyph_case_findings_total",
    ] {
        let value = sum_metric(&samples, name);
        if value > 0.0 {
            cases_found = value;
            break;
        }
        cases_found = cases_found.max(value);
    }

    Ok(DashboardMetrics {
        failures,
        queue_depth,
        avg_latency_ms,
        cases_found,
        events_total,
        queue_drops,
        latency_buckets,
        plugin_errors,
    })
}

#[tauri::command]
async fn list_flows(
    api: State<'_, GlyphApi>,
    replay: State<'_, ReplayState>,
    cursor: Option<String>,
    limit: Option<u32>,
    filters: Option<FlowFilters>,
) -> Result<FlowPage, String> {
    if let Some(page) = {
        let guard = replay.current.lock().map_err(|err| err.to_string())?;
        guard.as_ref().map(|dataset| {
            let total = dataset.flows.len();
            let start = cursor
                .as_deref()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0)
                .min(total);
            let chunk_size = limit.unwrap_or(200) as usize;
            let end = (start + chunk_size).min(total);
            let items = dataset.flows[start..end].to_vec();
            let next_cursor = if end < total {
                Some(end.to_string())
            } else {
                None
            };
            FlowPage { items, next_cursor }
        })
    } {
        return Ok(page);
    }

    let mut url = Url::parse(&api.endpoint("flows")).map_err(|err| err.to_string())?;
    let filters = filters.unwrap_or_default();

    {
        let mut pairs = url.query_pairs_mut();
        if let Some(cursor) = cursor {
            let trimmed = cursor.trim();
            if !trimmed.is_empty() {
                pairs.append_pair("cursor", trimmed);
            }
        }
        if let Some(limit) = limit {
            pairs.append_pair("limit", &limit.to_string());
        }
        if let Some(search) = filters
            .search
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            pairs.append_pair("search", search);
        }
        for method in filters
            .methods
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            pairs.append_pair("method", method);
        }
        for status in &filters.statuses {
            pairs.append_pair("status", &status.to_string());
        }
        for domain in filters
            .domains
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            pairs.append_pair("domain", domain);
        }
        for scope in filters
            .scope
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            pairs.append_pair("scope", scope);
        }
        for tag in filters
            .tags
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            pairs.append_pair("tag", tag);
        }
        for plugin_tag in filters
            .plugin_tags
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            pairs.append_pair("pluginTag", plugin_tag);
        }
    }

    let response = api
        .client
        .get(url)
        .send()
        .await
        .map_err(|err| err.to_string())?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(ApiError::UnexpectedResponse { status, body }.to_string());
    }

    response
        .json::<FlowPage>()
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn stream_events(
    app: tauri::AppHandle,
    api: State<'_, GlyphApi>,
    run_id: String,
) -> Result<(), String> {
    let window = app
        .get_window("main")
        .ok_or_else(|| ApiError::WindowMissing.to_string())?;

    let url = api.endpoint(&format!("runs/{}/events", run_id));
    let client = api.client.clone();
    let window_clone = window.clone();
    let run_id_clone = run_id.clone();
    let stream_key = build_stream_key("run", &run_id);

    let (abort_handle, abort_reg) = futures::future::AbortHandle::new_pair();

    let forward = async move {
        let response = client.get(url).send().await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ApiError::UnexpectedResponse { status, body });
        }

        let mut buffer = String::new();
        let mut byte_stream = response.bytes_stream();

        while let Some(chunk) = byte_stream.next().await {
            let chunk = chunk?;
            buffer.push_str(&String::from_utf8_lossy(&chunk));

            while let Some(index) = buffer.find('\n') {
                let line = buffer[..index].trim().to_string();
                buffer = buffer[index + 1..].to_string();

                if line.is_empty() {
                    continue;
                }

                let payload = if let Some(data) = line.strip_prefix("data:") {
                    data.trim().to_string()
                } else {
                    line
                };

                match from_str::<RunEvent>(&payload) {
                    Ok(event) => {
                        if let Err(err) =
                            emit_run_event(&window_clone, &run_id_clone, event.clone())
                        {
                            eprintln!("Failed to emit event: {err}");
                        }
                    }
                    Err(err) => {
                        eprintln!("Failed to parse event payload: {err}");
                    }
                }
            }
        }

        Ok::<(), ApiError>(())
    };

    let abortable = Abortable::new(forward, abort_reg);

    async_runtime::spawn(async move {
        match abortable.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => eprintln!("Stream error: {err}"),
            Err(_) => {}
        }
    });

    let mut guard = api.streams.lock().map_err(|err| err.to_string())?;
    if let Some(existing) = guard.insert(
        stream_key,
        StreamController {
            abort: abort_handle,
        },
    ) {
        existing.stop();
    }

    Ok(())
}

#[tauri::command]
async fn stop_stream(api: State<'_, GlyphApi>, run_id: String) -> Result<(), String> {
    let key = build_stream_key("run", &run_id);
    if let Some(controller) = api
        .streams
        .lock()
        .map_err(|err| err.to_string())?
        .remove(&key)
    {
        controller.stop();
    }

    Ok(())
}

#[tauri::command]
async fn stream_flows(
    app: tauri::AppHandle,
    api: State<'_, GlyphApi>,
    replay: State<'_, ReplayState>,
    stream_id: String,
    filters: Option<FlowFilters>,
) -> Result<(), String> {
    {
        let guard = replay.current.lock().map_err(|err| err.to_string())?;
        if guard.as_ref().is_some() {
            return Ok(());
        }
    }

    let window = app
        .get_window("main")
        .ok_or_else(|| ApiError::WindowMissing.to_string())?;

    let mut url = Url::parse(&api.endpoint("flows/events")).map_err(|err| err.to_string())?;
    let filters = filters.unwrap_or_default();
    {
        let mut pairs = url.query_pairs_mut();
        if let Some(search) = filters
            .search
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            pairs.append_pair("search", search);
        }
        for method in filters
            .methods
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            pairs.append_pair("method", method);
        }
        for status in &filters.statuses {
            pairs.append_pair("status", &status.to_string());
        }
        for domain in filters
            .domains
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            pairs.append_pair("domain", domain);
        }
        for scope in filters
            .scope
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            pairs.append_pair("scope", scope);
        }
        for tag in filters
            .tags
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            pairs.append_pair("tag", tag);
        }
        for plugin_tag in filters
            .plugin_tags
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            pairs.append_pair("pluginTag", plugin_tag);
        }
    }

    let client = api.client.clone();
    let window_clone = window.clone();
    let stream_id_clone = stream_id.clone();
    let stream_key = build_stream_key("flow", &stream_id);

    let (abort_handle, abort_reg) = futures::future::AbortHandle::new_pair();

    let forward = async move {
        let response = client.get(url).send().await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ApiError::UnexpectedResponse { status, body });
        }

        let mut buffer = String::new();
        let mut byte_stream = response.bytes_stream();

        while let Some(chunk) = byte_stream.next().await {
            let chunk = chunk?;
            buffer.push_str(&String::from_utf8_lossy(&chunk));

            while let Some(index) = buffer.find('\n') {
                let line = buffer[..index].trim().to_string();
                buffer = buffer[index + 1..].to_string();

                if line.is_empty() {
                    continue;
                }

                let payload = if let Some(data) = line.strip_prefix("data:") {
                    data.trim().to_string()
                } else {
                    line
                };

                match from_str::<FlowEventPayload>(&payload) {
                    Ok(event) => {
                        if let Err(err) =
                            emit_flow_event(&window_clone, &stream_id_clone, event.clone())
                        {
                            eprintln!("Failed to emit flow event: {err}");
                        }
                    }
                    Err(err) => {
                        eprintln!("Failed to parse flow event payload: {err}");
                    }
                }
            }
        }

        Ok::<(), ApiError>(())
    };

    let abortable = Abortable::new(forward, abort_reg);

    async_runtime::spawn(async move {
        match abortable.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => eprintln!("Stream error: {err}"),
            Err(_) => {}
        }
    });

    let mut guard = api.streams.lock().map_err(|err| err.to_string())?;
    if let Some(existing) = guard.insert(
        stream_key,
        StreamController {
            abort: abort_handle,
        },
    ) {
        existing.stop();
    }

    Ok(())
}

#[tauri::command]
async fn stop_flow_stream(api: State<'_, GlyphApi>, stream_id: String) -> Result<(), String> {
    let key = build_stream_key("flow", &stream_id);
    if let Some(controller) = api
        .streams
        .lock()
        .map_err(|err| err.to_string())?
        .remove(&key)
    {
        controller.stop();
    }

    Ok(())
}

#[tauri::command]
async fn resend_flow(
    api: State<'_, GlyphApi>,
    replay: State<'_, ReplayState>,
    flow_id: String,
    message: String,
) -> Result<ResendFlowResponse, String> {
    {
        let guard = replay.current.lock().map_err(|err| err.to_string())?;
        if guard.as_ref().is_some() {
            return Err("resending flows is unavailable while viewing an artifact".to_string());
        }
    }

    let url = api.endpoint(&format!("flows/{}/resend", flow_id));
    let payload = json!({ "message": message });
    let response = api
        .client
        .post(url)
        .json(&payload)
        .send()
        .await
        .map_err(|err| err.to_string())?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(ApiError::UnexpectedResponse { status, body }.to_string());
    }

    response
        .json::<ResendFlowResponse>()
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn fetch_scope_policy(api: State<'_, GlyphApi>) -> Result<ScopePolicyDocument, String> {
    let url = api.endpoint("scope/policy");
    let response = api
        .client
        .get(url)
        .send()
        .await
        .map_err(|err| err.to_string())?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(ApiError::UnexpectedResponse { status, body }.to_string());
    }

    let body = response.text().await.map_err(|err| err.to_string())?;
    let trimmed = body.trim_start();
    if trimmed.starts_with('{') {
        serde_json::from_str::<ScopePolicyDocument>(&body)
            .map_err(|err| err.to_string())
            .or_else(|_| {
                Ok(ScopePolicyDocument {
                    policy: body,
                    source: None,
                    updated_at: None,
                })
            })
    } else {
        Ok(ScopePolicyDocument {
            policy: body,
            source: None,
            updated_at: None,
        })
    }
}

#[tauri::command]
async fn validate_scope_policy(
    api: State<'_, GlyphApi>,
    policy: String,
) -> Result<ScopeValidationResult, String> {
    let url = api.endpoint("scope/policy/validate");
    let payload = json!({ "policy": policy });
    let response = api
        .client
        .post(url)
        .json(&payload)
        .send()
        .await
        .map_err(|err| err.to_string())?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(ApiError::UnexpectedResponse { status, body }.to_string());
    }

    response
        .json::<ScopeValidationResult>()
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn apply_scope_policy(
    api: State<'_, GlyphApi>,
    policy: String,
) -> Result<ScopeApplyResponse, String> {
    let url = api.endpoint("scope/policy/apply");
    let payload = json!({ "policy": policy });
    let response = api
        .client
        .post(url)
        .json(&payload)
        .send()
        .await
        .map_err(|err| err.to_string())?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(ApiError::UnexpectedResponse { status, body }.to_string());
    }

    response
        .json::<ScopeApplyResponse>()
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn parse_scope_text(
    api: State<'_, GlyphApi>,
    text: String,
) -> Result<ScopeParseResponse, String> {
    let url = api.endpoint("scope/policy/parse");
    let payload = json!({ "text": text });
    let response = api
        .client
        .post(url)
        .json(&payload)
        .send()
        .await
        .map_err(|err| err.to_string())?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(ApiError::UnexpectedResponse { status, body }.to_string());
    }

    response
        .json::<ScopeParseResponse>()
        .await
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn dry_run_scope_policy(
    api: State<'_, GlyphApi>,
    policy: Option<String>,
    urls: Vec<String>,
) -> Result<ScopeDryRunResponse, String> {
    let cleaned: Vec<String> = urls
        .into_iter()
        .map(|url| url.trim().to_string())
        .filter(|url| !url.is_empty())
        .collect();

    if cleaned.is_empty() {
        return Ok(ScopeDryRunResponse {
            results: Vec::new(),
        });
    }

    let mut payload = json!({ "urls": cleaned });
    if let Some(policy_value) = policy.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }) {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("policy".to_string(), json!(policy_value));
        }
    }

    let url = api.endpoint("scope/policy/dry-run");
    let response = api
        .client
        .post(url)
        .json(&payload)
        .send()
        .await
        .map_err(|err| err.to_string())?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(ApiError::UnexpectedResponse { status, body }.to_string());
    }

    response
        .json::<ScopeDryRunResponse>()
        .await
        .map_err(|err| err.to_string())
}

fn configure_devtools(window: &Window) {
    let allow_devtools =
        std::env::var("GLYPH_ENABLE_DEVTOOLS").map(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    if let Ok(true) = allow_devtools {
        let _ = window.open_devtools();
    }
}

fn main() {
    tauri::Builder::default()
        .manage(GlyphApi::new())
        .manage(ReplayState::new())
        .manage(CrashReportState::new())
        .setup(|app| {
            if let Some(window) = app.get_window("main") {
                configure_devtools(&window);
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            open_artifact,
            artifact_status,
            list_cases,
            list_runs,
            start_run,
            list_flows,
            stream_events,
            stop_stream,
            stream_flows,
            stop_flow_stream,
            resend_flow,
            fetch_metrics,
            prepare_crash_report,
            save_crash_report,
            fetch_scope_policy,
            validate_scope_policy,
            apply_scope_policy,
            parse_scope_text,
            dry_run_scope_policy
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
