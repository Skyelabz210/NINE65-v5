Now I have everything needed. Let me produce the audit report.

# CONSULTANT AUDIT

**Consultant**: Claude
**Model**: opus
**Timestamp**: 2026-02-10T21:38:40.052114
**Project**: v5

---

## EXECUTIVE SUMMARY

The FHE microservice plan is architecturally sound and its implementation is substantially complete—workspace isolation, modular decomposition, session management, wire types, HTTP hardening, and the Python SDK are all in place with working tests. However, the implementation diverges from the plan in two material ways: **HVT-2 (GSO-FHE `gso_mul`) is entirely unimplemented** in the handler dispatch, and the **Python SDK's `_eval_plain` method sends the scalar in the wrong wire field** (`inputs` array instead of `scalar`), which will fail at runtime. Additionally, five `RwLock::unwrap()` calls present a silent deadlock/panic surface that should be addressed before any production deployment.

---

## SYSTEM OVERVIEW

The plan restructures Python integration for the NINE65 FHE engine from a PyO3 cdylib binding (81+ compilation errors from pyo3 API churn) to an HTTP microservice architecture. The core workspace (`nine65`, `clockwork-core`, `nexgen_rational`, `mana`, `unhal`) stays permanently clean via Cargo workspace `exclude` directives, while a new `fhe-service` crate provides an HTTP boundary. A pure-Python SDK (`sdks/python/nine65_sdk/`) communicates via JSON+base64.

**Current implementation status against the 10-step plan:**

| Step | Description | Status |
|------|-------------|--------|
| 1 | Workspace isolation (Cargo.toml exclude) | **Done** |
| 2 | fhe-service Cargo.toml deps | **Done** |
| 3 | Extract `http.rs` + MAX_BODY_BYTES (HVT-4) | **Done** |
| 4 | Add `wire.rs` serde types | **Done** |
| 5 | Add `session.rs` with NoiseBudget (HVT-1) | **Done** |
| 6 | Add `handlers.rs` with FHE ops + gso_mul (HVT-2) | **Partial — gso_mul missing** |
| 7 | Rewrite `main.rs` with routing + connection limit (HVT-4) | **Done** |
| 8 | Rust tests using test_fast() (HVT-3) | **Partial — uses secure_128 not test_fast()** |
| 9 | Python SDK | **Done (bug in _eval_plain)** |
| 10 | Integration test | **Done** |

---

## RIGOR & CORRECTNESS REVIEW

### Finding 1: HVT-2 (`gso_mul`) Not Implemented — Plan/Code Gap

**Severity: High (functional gap)**

The plan explicitly calls out GSO-FHE depth-50 as a "High-Value Target" and specifies `gso_mul` as an operation in the evaluate endpoint (lines 192, 72–74 of the plan). The wire type's `Operation.op` doc comment (wire.rs:87) lists only `"add", "sub", "negate", "add_plain", "mul_plain", "mul"` — no `gso_mul`. The handler dispatch (handlers.rs:299–387) has no `"gso_mul"` match arm; it falls through to `"unknown operation"`.

This is NINE65's core differentiator. Shipping without it reduces the microservice to a standard BFV evaluator.

### Finding 2: Python SDK `_eval_plain` Sends Scalar in Wrong Field

**Severity: High (runtime bug)**

`session.py:128`:
```python
body = self._evaluate([{"op": op, "inputs": [ct.data, str(int(scalar))]}])
```

This sends the scalar as a second element of the `inputs` array. But the server-side `Operation` struct (wire.rs:86–94) expects `scalar` as a separate JSON field:
```rust
pub struct Operation {
    pub op: String,
    pub inputs: Vec<String>,
    #[serde(default)]
    pub scalar: Option<u64>,
}
```

The handler (handlers.rs:335–337) reads `op.scalar.ok_or_else(...)`. When `add_plain` or `mul_plain` is called from the Python SDK, `scalar` will be `None` (it was sent inside `inputs`), causing "add_plain requires scalar" / "mul_plain requires scalar" errors. Meanwhile the extra string in `inputs` means `cts.len() != 1`, so it would actually fail with "add_plain requires exactly 1 input" before even reaching the scalar check.

The correct SDK code should be:
```python
body = self._evaluate([{"op": op, "inputs": [ct.data], "scalar": int(scalar)}])
```

### Finding 3: `RwLock::unwrap()` — Poison Propagation Risk

**Severity: Medium (correctness)**

Five `unwrap()` calls on `RwLock` operations in `session.rs:177,191,200,206,212`. If any thread panics while holding the write lock (e.g., during keygen OOM, bincode serialization failure), the lock becomes poisoned and **all subsequent requests on all sessions** will panic with `PoisonError`. In a service handling concurrent connections via `std::thread::spawn`, this turns a single-session failure into a service-wide crash cascade.

Mitigation: use `.read().unwrap_or_else(|e| e.into_inner())` or `.write().unwrap_or_else(|e| e.into_inner())` (recover from poison), or catch panics at the connection level.

### Finding 4: `#![deny(clippy::float_arithmetic)]` Missing from fhe-service

**Severity: Medium (policy compliance)**

The plan's security gap table (line 54) identifies this as a medium-severity issue: "Add to fhe-service lib." The security gap was identified but not remediated—no `deny` or `forbid` directive exists in any fhe-service source file. While the current code is float-free, this lint would prevent regressions.

### Finding 5: TrackedEvaluator Not Actually Used

**Severity: Low (plan vs implementation)**

HVT-1 specifies using `TrackedEvaluator` as the session evaluator. The actual implementation (handlers.rs:283–287) creates a raw `BFVEvaluator` and manually calls `session.noise_budget.consume(...)` for each operation. This duplicates the tracking logic that `TrackedEvaluator` already encapsulates. Functionally equivalent, but the manual tracking is more error-prone (e.g., the negate cost of `100` millibits at line 327 is a magic number not derived from any `NoiseBudget` method).

---

## FUNCTIONAL & SCALABILITY ANALYSIS

### Strengths

1. **Clean architectural separation.** The monolithic 502-line `main.rs` has been decomposed into four well-scoped modules (`http.rs`, `session.rs`, `wire.rs`, `handlers.rs`) plus a thin `main.rs` entry point. Module boundaries match conceptual boundaries.

2. **Defense in depth on inputs.** The validation layer is thorough:
   - Body size limit before reading (http.rs:67)
   - Header size limit (http.rs:106)
   - Connection count limit (main.rs:65)
   - Session count limit (session.rs:178)
   - Per-field string length limits (wire.rs:6–10)
   - Ciphertext field size limits (wire.rs:9–10)
   - Operation count limits (wire.rs:155)
   - Value count limits (wire.rs:125)
   - Ciphertext validation on deserialization (session.rs:156)

3. **Correct ciphertext validation.** `Ciphertext::from_bytes_validated()` checks degree and modulus against session config, preventing cross-session ciphertext replay or malformed polynomial attacks.

4. **Python SDK is clean and idiomatic.** Context manager for session cleanup, opaque `Ciphertext` wrapper, typed error hierarchy, integer-only guarantee documented.

5. **Rust test coverage is solid.** 13 unit tests covering lifecycle, routing, roundtrip, add, add_plain, noise tracking, max sessions, and invalid session paths.

### Bottlenecks & Limitations

1. **Thread-per-connection model.** Each TCP connection spawns an OS thread (main.rs:74). At `MAX_CONNECTIONS=256` with `secure_256` sessions, each keygen allocates ~200MB. This is a 50GB theoretical memory ceiling. The plan acknowledges this implicitly by capping connections, but doesn't document the memory relationship.

2. **Global write lock for session mutation.** Every encrypt/decrypt/evaluate operation acquires a write lock on the entire `HashMap<String, Session>` (session.rs:200). This serializes all mutation across all sessions. With 256 concurrent connections, this is the primary throughput bottleneck. A sharded lock (`DashMap` or manual sharding) would allow concurrent mutations on different sessions.

3. **No request timeout on handler execution.** The 5-second read timeout (main.rs:87) only guards the parse phase. A `secure_256` multiply can take 444ms—a chain of 256 operations in a single evaluate request could take 113 seconds, holding a thread and write lock the entire time.

4. **No session TTL/reaper.** Acknowledged as Phase 2, but worth noting that orphaned sessions (client crashes without DELETE) leak memory permanently in the current implementation.

### Trade-off Analysis

| Design Choice | Benefit | Cost |
|---------------|---------|------|
| No async runtime (raw TCP) | Zero dependency on tokio/hyper, minimal attack surface | Thread-per-conn scalability limit, no backpressure |
| bincode + base64 for ciphertexts | Compact wire format (~33% overhead vs raw binary) | Requires validated deserialization, no human-readable debugging |
| Session-level NoiseBudget | Server-side budget enforcement prevents silent decryption failures | Budget estimates are approximate (not actual noise measurement) |
| OS CSPRNG for production keygen | Proper security, no seed management | Keygen is non-deterministic, harder to reproduce issues |

---

## UTILITY & DESIGN INTEGRITY

### API Design Quality

The REST API is well-structured with consistent naming, proper HTTP status codes (404 for missing session, 422 for noise exhaustion, 429 for capacity), and the Prometheus metrics endpoint follows conventions. The evaluate endpoint's batch operation model (array of operations in one request) is pragmatic—it reduces round trips while keeping the mental model simple.

**One design concern:** The evaluate endpoint processes operations sequentially and returns results positionally, but there's no way to reference a previous operation's output as input to a later operation in the same batch. This means multi-step circuits require one HTTP round trip per level. For a depth-50 circuit, that's 50 HTTP calls. Consider adding a `"ref:0"` syntax for operation chaining within a batch (Phase 2 candidate).

### Error Reporting Quality

Error responses use a consistent `{"error": {"code": "...", "message": "..."}}` structure. Server-side details are logged via `eprintln!` and not leaked to clients (main.rs:98). The error codes are machine-parseable (`NOISE_BUDGET_EXCEEDED`, `SESSION_NOT_FOUND`, etc.), enabling the SDK to map them to typed exceptions.

**Gap:** The Python SDK's error parsing (client.py:83–86) reads `body.get("error")` and `body.get("error_code")`, but the actual wire format nests these as `body["error"]["code"]` and `body["error"]["message"]`. The SDK will display the entire error dict as the message string rather than extracting the human-readable message. This is a cosmetic bug—errors are still raised, just with less-helpful messages.

### Maintainability

The codebase is small (~650 lines of Rust across 5 files, ~250 lines of Python across 5 files) and each module has a single responsibility. The Python SDK has no Rust dependency, so it can be versioned and released independently. The `#[cfg(test)]` gating on `ShadowHarvester` usage in session.rs correctly separates deterministic test paths from production CSPRNG paths.

---

## PRIORITIZED RECOMMENDATIONS

### P0 — Must Fix Before First Use

1. **Implement `gso_mul` in `handlers.rs`.** Add a `"gso_mul"` match arm that instantiates `GSOFHEContext`, wraps ciphertexts in `GSOCiphertext`, and calls `mul_symmetric()`. This is the plan's HVT-2 and NINE65's core differentiator. Without it, the service is a generic BFV wrapper.

2. **Fix Python SDK `_eval_plain` wire format.** Change `session.py:128` to send scalar as `"scalar": int(scalar)` in the operation dict, not as a second element of `inputs`. Current code will produce "requires exactly 1 input" errors for all `add_plain`/`mul_plain` calls. **Note:** The Rust-side tests in `main.rs` construct JSON directly and work fine—only the SDK path is broken.

### P1 — Should Fix Before Release

3. **Fix Python SDK error field extraction.** In `client.py:83–86`, change from `body.get("error")` to `body.get("error", {}).get("message", "Unknown error")` and similarly for `error_code` → `body.get("error", {}).get("code")`. The current code will display `{'code': 'SESSION_NOT_FOUND', 'message': 'session does not exist'}` as the exception message.

4. **Add `#![deny(clippy::float_arithmetic)]` to fhe-service.** Add to `main.rs` as a crate-level attribute. This was explicitly identified in the plan's security gap table.

5. **Handle `RwLock` poisoning gracefully.** Replace `.unwrap()` on lock acquisition with `.unwrap_or_else(|e| e.into_inner())` in `SessionStore` methods, or catch panics at the connection handler level with `std::panic::catch_unwind()`. Currently a single panicking thread can cascade to service-wide unavailability.

### P2 — Should Address in Phase 1.1

6. **Use `TrackedEvaluator` instead of manual budget tracking.** Replace the manual `session.noise_budget.consume(...)` calls in `handle_evaluate` with a `TrackedEvaluator` wrapping the session's evaluator. This eliminates the magic constant at line 327 (`100` for negate cost) and ensures cost calculations stay in sync with the core library.

7. **Add evaluate-level timeout.** Introduce a `MAX_EVALUATE_DURATION` constant (e.g., 30 seconds). After each operation in the batch, check elapsed time and return a partial result with an error if exceeded. This prevents a malicious batch of 256 `mul` operations from holding a thread for minutes.

8. **Add `gso_mul` to the Python SDK.** Once the server-side handler exists, add a `gso_mul` method to `Session` that delegates to `_eval_binary("gso_mul", ct_a, ct_b)`.

### P3 — Phase 2 Candidates

9. **Shard the session store.** Replace `RwLock<HashMap<String, Session>>` with per-session `Mutex` or `DashMap` to allow concurrent mutations on different sessions.

10. **Add operation chaining in evaluate batches.** Allow `"ref:N"` syntax in `inputs` to reference the result of operation N in the same batch, eliminating round trips for multi-level circuits.

11. **Add session TTL with reaper.** Spawn a background thread that evicts sessions older than a configurable TTL (default: 1 hour). This prevents memory leaks from orphaned sessions.

---

## RAW OBSERVATIONS

- **Test infrastructure (HVT-3) partially used.** The plan specifies using `SecureConfig::test_fast()` for fast tests, but the existing tests use `secure_128`, which does full keygen. This makes each test that creates a session significantly slower than it needs to be. The `new_test` method exists in `session.rs:95` with deterministic seeding, but the `main.rs` tests don't use it—they call `handle_create_session` which always goes through `Session::new()` with CSPRNG. To benefit from HVT-3, tests would need a feature-gated fast path or direct `SessionStore` insertion.

- **`exact_transcendentals` crate is in the workspace architecture diagram** (plan line 14) but is not listed in the workspace `members` of `Cargo.toml`. It may be a separate out-of-workspace crate, but the plan implies it's part of the "always green" core workspace. Worth verifying.

- **Connection limit race condition.** The `fetch_add(1, Ordering::Relaxed)` at main.rs:64 followed by comparison is correct for limiting but uses `Relaxed` ordering. Two threads could both see `current < max_connections` and both proceed when only one should. In practice this allows at most `max_connections + num_cpus` concurrent connections, which is acceptable for a safety bound but should be documented.

- **No `Content-Length` validation for `0` body on encrypt/decrypt.** If a client sends `Content-Length: 0` on `POST /v1/sessions/{id}/encrypt`, the handler receives an empty body, `serde_json::from_slice` fails, and a 400 is returned. This is correct behavior, but the error message ("malformed JSON") could be more specific.

- **Session creation returns 200 instead of 201.** REST convention uses `201 Created` for resource creation. The current implementation returns `200 OK` (handlers.rs:168). Low priority but violates HTTP semantics.

- **The `_eval_plain` scalar encoding as `str(int(scalar))` would also fail even if placed in the right field**, because the server deserializes `scalar` as `Option<u64>`. A JSON string `"5"` would fail to deserialize as `u64`. The fix (sending as integer in the `scalar` field) resolves both issues simultaneously.

- **`test_negate_ciphertext` in Python integration tests expects `-42`.** BFV decryption returns values modulo `t`. Whether `-42` maps correctly depends on how the decryptor handles negation—if `t` is large and the implementation returns the centered representative, this works. If it returns the positive representative (`t - 42`), the test will fail. This should be verified against the actual `BFVDecryptor.decrypt()` behavior for negated ciphertexts.
