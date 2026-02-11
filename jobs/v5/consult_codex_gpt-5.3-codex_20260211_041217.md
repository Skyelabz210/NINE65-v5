# CONSULTANT AUDIT

**Consultant**: Codex  
**Model**: gpt-5.3-codex  
**Timestamp**: 2026-02-11T04:12:17.315812  
**Project**: v5

## EXECUTIVE SUMMARY
The current microservice isolation strategy is directionally correct and already delivering workspace stability, but several remaining items are production blockers rather than optional hardening. The largest risks are concurrency/resource control (global session write lock, thread-per-connection, forced connection close, no response-size guard) and semantic correctness of noise-budget reporting. The plan is close, but it needs stricter execution gates and a clearer API compatibility strategy to avoid regressions during finalization.

## SYSTEM OVERVIEW
The active plan migrates Python integration from in-process PyO3 bindings to an HTTP boundary, with Rust `nine65` as the cryptographic core and a pure Python SDK as client (`jobs/v5/CURRENT_CONTEXT_20260211_041217.md:5`, `jobs/v5/CURRENT_CONTEXT_20260211_041217.md:9`).  
Current service behavior is session-centric (`/v1/sessions/*`) with server-side key custody and JSON/base64 ciphertext transport (`crates/fhe-service/src/handlers.rs:145`, `crates/fhe-service/src/handlers.rs:194`, `crates/fhe-service/src/session.rs:46`).  
The workspace exclusion of legacy Python/WASM crates is in place (`Cargo.toml:3`), which achieves the intended decoupling objective.

## RIGOR & CORRECTNESS REVIEW
1. `allow_insecure` is still runtime-guarded, not compile-time-blocked for release consumers.  
Evidence: runtime assert pattern exists in `crates/nine65/src/params/secure_configs.rs:241`; no `compile_error!` guard appears in `crates/nine65/src/lib.rs` (only doc mentions at `crates/nine65/src/lib.rs:77`).

2. Noise budget accounting is incomplete in encrypt flow.  
Evidence: `handle_encrypt` performs encryption but never consumes budget (`crates/fhe-service/src/handlers.rs:213`, `crates/fhe-service/src/handlers.rs:227`), while `encrypt_cost` exists (`crates/nine65/src/noise/budget.rs:171`).

3. Multiplication noise semantics are currently inconsistent across code paths.  
Evidence: service uses `mul_no_relin` + `relinearize` (`crates/fhe-service/src/handlers.rs:390`) and that path has no explicit rescale step (`crates/nine65/src/ops/homomorphic.rs:102`, `crates/nine65/src/ops/homomorphic.rs:181`), while dual-RNS tracked path explicitly credits rescale gain (`crates/nine65/src/ops/rns_fhe.rs:3180`).  
Inference: CF-6 should be treated as a model-alignment decision, not a guaranteed bug fix.

4. Error-message secrecy is inconsistent across endpoints.  
Evidence: evaluate errors include actual plaintext modulus in message (`crates/fhe-service/src/handlers.rs:336`, `crates/fhe-service/src/handlers.rs:355`), while encrypt has an explicit non-leak test (`crates/fhe-service/src/main.rs:562`).

5. One stated security gap in the current plan is already stale.  
Evidence: plan says no float-arithmetic deny (`jobs/v5/CURRENT_CONTEXT_20260211_041217.md:176`), but service already enforces it (`crates/fhe-service/src/main.rs:6`).  
This indicates plan drift risk in remaining execution.

## FUNCTIONAL & SCALABILITY ANALYSIS
1. Mutating operations are globally serialized by lock design.  
Evidence: `RwLock<HashMap<String, Session>>` plus full-map write lock for every mutating session operation (`crates/fhe-service/src/session.rs:163`, `crates/fhe-service/src/session.rs:196`).

2. Connection model imposes avoidable overhead and saturation risk.  
Evidence: one OS thread per connection (`crates/fhe-service/src/main.rs:76`), forced `Connection: close` (`crates/fhe-service/src/http.rs:151`), read timeout but no write timeout (`crates/fhe-service/src/main.rs:89`).

3. Body-size guard exists, but client semantics are degraded.  
Evidence: parser can classify oversized body (`crates/fhe-service/src/http.rs:24`), yet server maps all parse errors to generic 400 (`crates/fhe-service/src/main.rs:97`) instead of 413.

4. Request limits do not cap response amplification.  
Evidence: encrypt allows up to 1024 values (`crates/fhe-service/src/wire.rs:125`) and returns ciphertext arrays (`crates/fhe-service/src/wire.rs:58`), with no response-body ceiling in write path (`crates/fhe-service/src/http.rs:145`).  
Operationally, this is a memory and bandwidth pressure vector under load.

5. Throughput evidence in the plan is not service-layer evidence.  
Evidence: plan marks throughput done via `throughput.rs` (`jobs/v5/CURRENT_CONTEXT_20260211_041217.md:37`), but benchmark file is core crypto bench (`crates/nine65/benches/throughput.rs:1`), not HTTP/session throughput.

6. Session lifecycle control remains incomplete for long-running uptime.  
Evidence: no TTL, no `last_accessed`, no reaper fields in `Session`/`SessionStore` (`crates/fhe-service/src/session.rs:46`, `crates/fhe-service/src/session.rs:162`).

## UTILITY & DESIGN INTEGRITY
1. Service docs are materially outdated vs live API.  
Evidence: README still documents `/v1/fhe/*` (`crates/fhe-service/README.md:8`) while router serves `/v1/sessions/*` (`crates/fhe-service/src/handlers.rs:43`).

2. Test artifacts still encode old route mental model.  
Evidence: HTTP parser unit test uses `/v1/fhe/public-key` (`crates/fhe-service/src/http.rs:210`).

3. Planned wire-field rename is a contract break without migration strategy.  
Evidence: SDK currently hardcodes `noise_budget_millibits` (`sdks/python/nine65_sdk/client.py:161`, `sdks/python/nine65_sdk/session.py:64`).

4. SDK tests exist but are not CI-gated in workspace pipeline.  
Evidence: CI runs cargo tests (`.github/workflows/ci.yml:95`), while Python integration tests require a live service (`sdks/python/tests/test_roundtrip.py:3`).

## PRIORITIZED RECOMMENDATIONS
1. Set three hard release gates before further feature work: CF-1 compile guard, CF-2 encrypt budget consume, CF-4 per-session lock refactor.  
Acceptance: each has dedicated regression tests plus load sanity test.

2. Add protocol-correct parse error mapping now (400 vs 413) and preserve machine-readable error codes.  
Acceptance: oversized body returns 413 deterministically; parser tests cover this path.

3. Add response-size governance to complement request-size governance.  
Acceptance: explicit max response bytes and preflight rejection for oversized encrypt/evaluate batches.

4. Clarify and freeze noise model semantics for this API version.  
Acceptance: either keep “estimate” terminology with documented heuristic bounds, or expose model type/version in response metadata.

5. Treat CF-6 as a design decision checkpoint.  
Acceptance: document whether current service multiplication path includes rescale-equivalent gain; adjust budget formula only after this decision.

6. Implement TTL with lazy eviction first, background reaper second.  
Acceptance: sessions expire under inactivity; eviction path preserves key zeroization guarantees.

7. Add compatibility plan for wire-field rename (`noise_budget_millibits` to estimate form).  
Acceptance: dual-field or versioned endpoint for one deprecation window; SDK updated in same change set.

8. Bring SDK contract tests into CI with ephemeral service startup.  
Acceptance: CI fails on API/SDK drift without manual local setup.

9. Align docs/tests with current routing immediately to reduce operator error.  
Acceptance: README and parser tests updated to `/v1/sessions/*`.

10. Add service-level performance and contention instrumentation (latency histogram, lock-wait time, queue/connection saturation).  
Acceptance: dashboard-ready metrics for p50/p95/p99 and active lock contention.

## RAW OBSERVATIONS
1. Analysis is static/evidence-based from current repository artifacts; no build/test execution was performed in this consultation pass.  
2. The current plan has high-quality prioritization structure, but several “high” items are actually reliability-critical under moderate concurrency.  
3. The workspace decoupling objective is achieved; remaining risk is mostly at the service boundary (protocol, lifecycle, and operational safeguards).
