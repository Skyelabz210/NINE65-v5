# fhe-service

Rust HTTP service that exposes the FHE boundary for the telemetry gateway.

Implemented endpoints:
- `GET /healthz`
- `GET /v1/version`
- `GET /v1/fhe/public-key`
- `POST /v1/fhe/evaluate`
- `GET /v1/metrics`

Notes:
- Uses `SecureConfig::secure_192()` metadata from `nine65`.
- Enforces a minimum noise budget policy in evaluate requests.
- Intended for staging/dev integration; NINE65 v5 is pre-production.

Run locally:
```bash
cargo run -p fhe-service --release
```
