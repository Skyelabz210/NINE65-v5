# CONSULTANT AUDIT

**Consultant**: Codex  
**Model**: gpt-5.1-codex-max  
**Timestamp**: 2026-02-10T21:38:40.049557  
**Project**: v5

## EXECUTIVE SUMMARY
- The microservice split is largely in place (workspace excludes, service modularized, Python SDK added), but two contract-level correctness bugs make plaintext ops unusable from Python and negate semantics inconsistent with the service.  
- High-value differentiators (GSO depth-50, TrackedEvaluator-based noise accounting) are still absent from the live handler path, so the new boundary currently delivers only baseline BFV.  
- Security hardening is partial: size limits and connection caps exist, yet error leakage, missing request IDs, and unchecked plaintext scalars leave obvious attack and telemetry gaps.

## SYSTEM OVERVIEW
- Current plan: keep Rust FHE core green by isolating Python via an HTTP microservice; Python SDK becomes a pure HTTP client.  
- Service layout implemented (`main.rs`, `http.rs`, `session.rs`, `wire.rs`, `handlers.rs`) with body-size and connection limits; sessions hold keys and noise budget; evaluate endpoint supports add/sub/negate/add_plain/mul_plain/mul.  
- Python SDK (`sdks/python/nine65_sdk`) wraps the HTTP API with integration tests marked `@integration`.

## RIGOR & CORRECTNESS REVIEW
- Python plaintext ops are miswired: `Session._eval_plain` sends the scalar as a second ciphertext input instead of the `scalar` field expected by the server; requests will fail base64 validation (`sdks/python/nine65_sdk/session.py:121-135` vs `crates/fhe-service/src/handlers.rs:331-359`).  
- Signed decoding is undefined: server decrypt returns `u64` in `[0,t)` (`handlers.rs:249-264`), but SDK tests expect negative results for `negate` (e.g., `-42`); no centered-lift is performed, so tests will fail and client semantics are unclear.  
- HVT-2 (GSO depth-50) not integrated: evaluate handler lacks `gso_mul` and sessions never enter `GSOFHEContext`, so the advertised differentiator is unavailable (`handlers.rs:299-387`).  
- HVT-1 only partially realized: noise budget is manually decremented with fixed costs; `TrackedEvaluator` is not used, so budget does not reflect actual op noise and can drift (same section).  
- Scalars for `add_plain`/`mul_plain` are not range-checked against `t`; overflow or hostile scalars can silently wrap and desynchronize noise tracking (`handlers.rs:331-359`).  
- Tests use production `secure_128` parameters; fast/seeded configs from HVT-3 are unused, making the suite slower and less deterministic.

## FUNCTIONAL & SCALABILITY ANALYSIS
- Thread-per-connection server with only a 5s read timeout; heavy mul chains can hold threads indefinitely. Per-request op count is capped (256) but each mul is O(n log n); no execution timeout or queueing (`main.rs:34-83`, `handlers.rs:272-417`).  
- Connection limiter works, yet relies on bespoke HTTP parser; no keep-alive or pipelining, so throughput under load will be limited; MAX_BODY_BYTES enforcement depends on `Content-Length`, not chunked decoding (`http.rs:12-91`).  
- SessionStore caps count but has no TTL/reaper; long-lived idle sessions hold keys and memory until manual DELETE (`session.rs:68-137`).  
- Prometheus metrics exist but omit latency, noise exhaustion counts, and rejection reasons, limiting observability (`handlers.rs:120-143`).  
- Python SDK uses a shared `requests.Session` but lacks retries/backoff; any transient 503 causes immediate failure (`client.py:21-71`).

## UTILITY & DESIGN INTEGRITY
- API contract drift between server and SDK (plaintext ops, signed decoding) undermines developer trust; docs/examples need to match actual wire format.  
- Error responses leak internal details such as plaintext modulus (`handlers.rs:214-218`) contrary to the plan’s “generic errors” requirement; no `x-request-id` propagation for correlation.  
- Security lint (`#![deny(clippy::float_arithmetic)]`) called out in the plan is not enabled in the crate root; risk of future float regressions.  
- Ciphertext validation is strong (`ct_from_b64` with `from_bytes_validated`), and MAX_CIPHERTEXT_FIELD_LEN guards are in place (`wire.rs:9-66`), aligning with stated body-size defenses.

## PRIORITIZED RECOMMENDATIONS
1) **Fix SDK ↔ API contract**: Send scalars via the `scalar` field and keep only one ciphertext input; add server-side scalar `< t` check and centered-lift decoding (or adjust SDK/tests) to resolve negate/sign semantics.  
2) **Ship HVTs as planned**: Add `gso_mul` path and GSO context wrapping; replace manual budget debits with `TrackedEvaluator` to align budget with actual operations.  
3) **Harden request handling**: Clamp plaintext scalars, mask modulus/error details, add request-id echo, and enforce `#![deny(clippy::float_arithmetic)]` in `fhe-service`.  
4) **Operational limits**: Add per-request execution timeout or bounded thread pool; consider work queue for mul-heavy requests to prevent connection exhaustion despite limits.  
5) **Test posture**: Switch service tests to `allow_insecure`/`test_fast` configs for speed and determinism; expand integration tests to cover gso_mul and noise exhaustion cases once implemented.  
6) **Observability**: Extend metrics with latency buckets, noise-budget-exhausted counters, and rejection reasons; log request-id with errors for correlation.

## RAW OBSERVATIONS
- Body/header size limits implemented (10MB / 64KB) match plan; connection limit defaults to 256 via env override.  
- Ciphertext serialization path (`ct_to_b64`/`ct_from_b64`) already centralizes validation, reducing accidental cross-config misuse.  
- Integration tests are marked `@integration` and require a running service; current contract bugs will cause `add_plain`/`mul_plain` cases to fail immediately.  
- Phase-2 roadmap items (rotations, packing, TTL) remain deferred; none of their hooks appear in the current codebase.
