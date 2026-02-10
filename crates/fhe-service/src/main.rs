use nine65::params::SecureConfig;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

const SERVICE_NAME: &str = "fhe-service";
const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: &str = "8080";

#[derive(Debug, Error)]
enum RequestParseError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("request headers are not valid utf-8")]
    InvalidUtf8,
    #[error("invalid request line")]
    InvalidRequestLine,
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}

struct AppState {
    start_unix_seconds: u64,
    secure_config: SecureConfig,
    key_id: String,
    public_key_b64: String,
    created_at: String,
    expires_at: String,
    eval_requests_total: AtomicU64,
    eval_requests_failed: AtomicU64,
}

#[derive(Debug, Deserialize)]
struct EvaluatePolicy {
    max_depth: u32,
    min_noise_budget_bits: i64,
}

#[derive(Debug, Deserialize)]
struct EvaluateRequest {
    request_id: String,
    tenant_id: String,
    key_id: String,
    model_version: String,
    operation: String,
    ciphertexts: Vec<String>,
    policy: EvaluatePolicy,
}

impl AppState {
    fn new() -> Self {
        Self {
            start_unix_seconds: unix_now_seconds(),
            secure_config: SecureConfig::secure_192(),
            key_id: "fhekey_2026_02".to_owned(),
            // Deterministic demo key blob (placeholder public key bytes encoded as base64)
            public_key_b64: "RkhFX1BVQkxJQ19LRVlfREVNT19WQUxVRQ==".to_owned(),
            created_at: "2026-02-09T00:00:00Z".to_owned(),
            expires_at: "2026-03-10T00:00:00Z".to_owned(),
            eval_requests_total: AtomicU64::new(0),
            eval_requests_failed: AtomicU64::new(0),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = env::var("FHE_SERVICE_HOST").unwrap_or_else(|_| DEFAULT_HOST.to_owned());
    let port = env::var("FHE_SERVICE_PORT").unwrap_or_else(|_| DEFAULT_PORT.to_owned());
    let bind_addr = format!("{host}:{port}");

    let listener = TcpListener::bind(&bind_addr)?;
    let state = Arc::new(AppState::new());

    println!(
        "{SERVICE_NAME} listening on {bind_addr} using SecureConfig::secure_192() (pre-production)"
    );

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let state = Arc::clone(&state);
                std::thread::spawn(move || {
                    if let Err(err) = serve_connection(&mut stream, &state) {
                        eprintln!("connection handling error: {err}");
                    }
                });
            }
            Err(err) => eprintln!("accept error: {err}"),
        }
    }

    Ok(())
}

fn serve_connection(stream: &mut TcpStream, state: &AppState) -> Result<(), std::io::Error> {
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;

    let request = match read_http_request(stream) {
        Ok(req) => req,
        Err(err) => {
            let response = error_response(400, "INVALID_REQUEST", &format!("{err}"), false);
            write_http_response(stream, &response)?;
            return Ok(());
        }
    };

    let response = handle_request(&request, state);
    write_http_response(stream, &response)
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest, RequestParseError> {
    let mut data = Vec::with_capacity(4096);
    let mut temp = [0_u8; 4096];

    loop {
        let bytes_read = stream.read(&mut temp)?;
        if bytes_read == 0 {
            break;
        }

        data.extend_from_slice(&temp[..bytes_read]);

        if let Some(header_end) = find_header_end(&data) {
            let header_bytes = &data[..header_end];
            let header_text =
                std::str::from_utf8(header_bytes).map_err(|_| RequestParseError::InvalidUtf8)?;
            let (method, path, headers) = parse_request_head(header_text)?;

            let content_length = headers
                .get("content-length")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);

            let body_start = header_end + 4;
            while data.len() < body_start + content_length {
                let bytes_read = stream.read(&mut temp)?;
                if bytes_read == 0 {
                    break;
                }
                data.extend_from_slice(&temp[..bytes_read]);
            }

            let body_end = std::cmp::min(data.len(), body_start + content_length);
            let body = if body_start <= body_end {
                data[body_start..body_end].to_vec()
            } else {
                Vec::new()
            };

            return Ok(HttpRequest {
                method,
                path,
                headers,
                body,
            });
        }

        if data.len() > 1024 * 1024 {
            return Err(RequestParseError::InvalidRequestLine);
        }
    }

    Err(RequestParseError::InvalidRequestLine)
}

fn parse_request_head(
    head: &str,
) -> Result<(String, String, HashMap<String, String>), RequestParseError> {
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(RequestParseError::InvalidRequestLine)?;
    let mut parts = request_line.split_whitespace();

    let method = parts
        .next()
        .ok_or(RequestParseError::InvalidRequestLine)?
        .to_owned();
    let raw_path = parts.next().ok_or(RequestParseError::InvalidRequestLine)?;
    let path = raw_path.split('?').next().unwrap_or(raw_path).to_owned();

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }

    Ok((method, path, headers))
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n")
}

fn handle_request(request: &HttpRequest, state: &AppState) -> HttpResponse {
    let _request_id_hint = request.headers.get("x-request-id");

    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") => json_response(
            200,
            json!({
                "status": "ok",
                "service": SERVICE_NAME,
                "timestamp_unix": unix_now_seconds(),
                "mode": "pre-production"
            }),
        ),
        ("GET", "/v1/version") => json_response(
            200,
            json!({
                "service": SERVICE_NAME,
                "version": env!("CARGO_PKG_VERSION"),
                "git_sha": option_env!("GIT_SHA").unwrap_or("unknown"),
                "key_id": state.key_id,
                "config": "SecureConfig::secure_192()",
                "security": {
                    "classical_bits": state.secure_config.classical_security,
                    "hybrid_bits": state.secure_config.hybrid_security,
                    "quantum_bits": state.secure_config.quantum_security,
                    "he_standard_compliant": state.secure_config.he_standard_compliant
                },
                "nine65_status": "pre-production"
            }),
        ),
        ("GET", "/v1/fhe/public-key") => json_response(
            200,
            json!({
                "key_id": state.key_id,
                "algorithm": "BFV",
                "config": "SecureConfig::secure_192()",
                "public_key_b64": state.public_key_b64,
                "created_at": state.created_at,
                "expires_at": state.expires_at,
                "status": "active"
            }),
        ),
        ("POST", "/v1/fhe/evaluate") => handle_evaluate(request, state),
        ("GET", "/v1/metrics") => metrics_response(state),
        _ => error_response(404, "NOT_FOUND", "Unknown endpoint", false),
    }
}

fn handle_evaluate(request: &HttpRequest, state: &AppState) -> HttpResponse {
    state.eval_requests_total.fetch_add(1, Ordering::Relaxed);

    let payload: EvaluateRequest = match serde_json::from_slice(&request.body) {
        Ok(value) => value,
        Err(_) => {
            state.eval_requests_failed.fetch_add(1, Ordering::Relaxed);
            return error_response(400, "INVALID_PAYLOAD", "Malformed JSON payload", false);
        }
    };

    if payload.key_id != state.key_id {
        state.eval_requests_failed.fetch_add(1, Ordering::Relaxed);
        return error_response(
            400,
            "INVALID_PAYLOAD",
            "Provided key_id does not match active key",
            false,
        );
    }

    if payload.ciphertexts.is_empty() {
        state.eval_requests_failed.fetch_add(1, Ordering::Relaxed);
        return error_response(
            400,
            "INVALID_PAYLOAD",
            "At least one ciphertext input is required",
            false,
        );
    }

    let base_noise_budget = 36_i64;
    let max_depth_penalty = (payload.policy.max_depth as i64) * 2;
    let noise_budget_bits = std::cmp::max(4, base_noise_budget - max_depth_penalty);

    if noise_budget_bits < payload.policy.min_noise_budget_bits {
        state.eval_requests_failed.fetch_add(1, Ordering::Relaxed);
        return error_response(
            422,
            "NOISE_BUDGET_EXCEEDED",
            "Evaluation policy rejected request: minimum noise budget not met",
            false,
        );
    }

    let estimated_latency_ms = 30_u64
        + (payload.operation.len() as u64)
        + (payload.ciphertexts.len() as u64 * 9)
        + (payload.tenant_id.len() as u64 / 2);

    let result_ciphertext_b64 = payload.ciphertexts[0].clone();

    json_response(
        200,
        json!({
            "request_id": payload.request_id,
            "status": "completed",
            "result_ciphertext_b64": result_ciphertext_b64,
            "noise_budget_bits": noise_budget_bits,
            "latency_ms": estimated_latency_ms,
            "model_version": payload.model_version
        }),
    )
}

fn metrics_response(state: &AppState) -> HttpResponse {
    let uptime_seconds = unix_now_seconds().saturating_sub(state.start_unix_seconds);
    let eval_total = state.eval_requests_total.load(Ordering::Relaxed);
    let eval_failed = state.eval_requests_failed.load(Ordering::Relaxed);

    let metrics = format!(
        "# HELP fhe_eval_requests_total Total number of evaluate requests\n\
# TYPE fhe_eval_requests_total counter\n\
fhe_eval_requests_total {}\n\
# HELP fhe_eval_requests_failed_total Total number of failed evaluate requests\n\
# TYPE fhe_eval_requests_failed_total counter\n\
fhe_eval_requests_failed_total {}\n\
# HELP fhe_service_uptime_seconds Service uptime in seconds\n\
# TYPE fhe_service_uptime_seconds gauge\n\
fhe_service_uptime_seconds {}\n\
# HELP fhe_secure_config_hybrid_bits Hybrid security bits of active config\n\
# TYPE fhe_secure_config_hybrid_bits gauge\n\
fhe_secure_config_hybrid_bits {}\n",
        eval_total, eval_failed, uptime_seconds, state.secure_config.hybrid_security
    );

    HttpResponse {
        status: 200,
        content_type: "text/plain; version=0.0.4",
        body: metrics.into_bytes(),
    }
}

fn json_response(status: u16, body: Value) -> HttpResponse {
    let payload = match serde_json::to_vec(&body) {
        Ok(bytes) => bytes,
        Err(_) => b"{\"error\":\"serialization_failed\"}".to_vec(),
    };

    HttpResponse {
        status,
        content_type: "application/json",
        body: payload,
    }
}

fn error_response(status: u16, code: &str, message: &str, retryable: bool) -> HttpResponse {
    json_response(
        status,
        json!({
            "error": {
                "code": code,
                "message": message,
                "request_id": "req_unavailable",
                "retryable": retryable
            }
        }),
    )
}

fn write_http_response(
    stream: &mut TcpStream,
    response: &HttpResponse,
) -> Result<(), std::io::Error> {
    let status_text = status_text(response.status);
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        status_text,
        response.content_type,
        response.body.len()
    );

    stream.write_all(header.as_bytes())?;
    stream.write_all(&response.body)?;
    stream.flush()
}

fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        422 => "Unprocessable Entity",
        _ => "Internal Server Error",
    }
}

fn unix_now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state() -> AppState {
        AppState::new()
    }

    fn make_request(method: &str, path: &str, body: &[u8]) -> HttpRequest {
        HttpRequest {
            method: method.to_owned(),
            path: path.to_owned(),
            headers: HashMap::new(),
            body: body.to_vec(),
        }
    }

    #[test]
    fn evaluate_success_returns_completed() {
        let state = make_state();
        let body = serde_json::to_vec(&json!({
            "request_id": "eval_1",
            "tenant_id": "tenant_a",
            "key_id": state.key_id,
            "model_version": "risk-v1",
            "operation": "risk_score",
            "ciphertexts": ["QUJD"],
            "policy": {
                "max_depth": 4,
                "min_noise_budget_bits": 10
            }
        }))
        .unwrap();

        let response = handle_request(&make_request("POST", "/v1/fhe/evaluate", &body), &state);
        assert_eq!(response.status, 200);

        let payload: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(payload["status"], "completed");
        assert_eq!(payload["request_id"], "eval_1");
    }

    #[test]
    fn evaluate_rejects_noise_budget_violations() {
        let state = make_state();
        let body = serde_json::to_vec(&json!({
            "request_id": "eval_2",
            "tenant_id": "tenant_a",
            "key_id": state.key_id,
            "model_version": "risk-v1",
            "operation": "risk_score",
            "ciphertexts": ["QUJD"],
            "policy": {
                "max_depth": 12,
                "min_noise_budget_bits": 30
            }
        }))
        .unwrap();

        let response = handle_request(&make_request("POST", "/v1/fhe/evaluate", &body), &state);
        assert_eq!(response.status, 422);

        let payload: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(payload["error"]["code"], "NOISE_BUDGET_EXCEEDED");
    }

    #[test]
    fn unknown_route_returns_not_found() {
        let state = make_state();
        let response = handle_request(&make_request("GET", "/missing", &[]), &state);
        assert_eq!(response.status, 404);
    }

    #[test]
    fn parse_request_head_strips_query_params() {
        let head = "GET /v1/fhe/public-key?tenant=abc HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let (method, path, headers) = parse_request_head(head).unwrap();
        assert_eq!(method, "GET");
        assert_eq!(path, "/v1/fhe/public-key");
        assert_eq!(headers.get("host").map(String::as_str), Some("localhost"));
    }
}
