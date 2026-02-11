# CONSULTANT AUDIT

**Consultant**: Claude
**Model**: opus
**Timestamp**: 2026-02-10T21:21:20.699761
**Project**: v5

---

## EXECUTIVE SUMMARY

The FHE microservice plan is well-architected and the implementation is substantially complete: workspace isolation is done, all 5 modules are extracted, 15 Rust unit tests pass, and the Python SDK is scaffolded with comprehensive integration tests. However, I identified one **confirmed wire-format bug** (Python SDK sends scalar in `inputs[]` instead of the `scalar` field), two **plan-stated HVTs that remain unimplemented** (GSO-FHE `gso_mul` and `TrackedEvaluator` integration), and several security hardening gaps (no `#![deny(clippy::float_arithmetic)]`, no write timeout, no request-ID tracking). The codebase is clean, compiles with only 1 fhe-service warning, and the test infrastructure is solid.

---

## SYSTEM OVERVIEW

The plan replaces a broken PyO3 binding layer (81+ compilation errors) with an HTTP microservice architecture. The Rust `fhe-service` crate acts as an HTTP boundary around the `nine65` FHE engine, and a pure-Python SDK (`nine65_sdk`) communicates via JSON/bincode-over-base64 REST endpoints. This permanently isolates external binding dependencies from the core workspace.

**Current state of implementation:**

| Component | Plan Status | Actual Status |
|-----------|------------|---------------|
| Workspace isolation (`Cargo.toml` exclude) | Step 1 | **Done** -- `exclude = ["fuzz", "crates/nine65-python", "crates/nine65-wasm"]` |
| fhe-service Cargo.toml | Step 2 | **Done** -- nine65/serde, base64, bincode, getrandom |
| `http.rs` extraction + body limits | Step 3 + HVT-4 | **Done** -- MAX_BODY_BYTES=10MB, MAX_HEADER_BYTES=64KB |
| `wire.rs` serde types | Step 4 | **Done** -- full validation suite |
| `session.rs` + SessionStore | Step 5 + HVT-1 (partial) | **Partial** -- Session + NoiseBudget present, but TrackedEvaluator not used |
| `handlers.rs` + evaluate ops | Step 6 + HVT-2 | **Partial** -- 6 ops implemented, `gso_mul` missing |
| `main.rs` rewrite + connection limit | Step 7 + HVT-4 | **Done** -- max connections enforced |
| Rust tests | Step 8 | **Done** -- 15 tests passing |
| Python SDK | Step 9 | **Done** -- client, session, ciphertext, errors |
| Integration tests | Step 10 | **Done** -- 13 integration tests written (require live service) |

---

## RIGOR & CORRECTNESS REVIEW

### FINDING 1 (Bug, Severity: Critical): Python SDK wire-format mismatch for plaintext operations

**File**: `sdks/python/nine65_sdk/session.py:126-129`

```python
def _eval_plain(self, op, ct, scalar):
    """Evaluate a ciphertext-plaintext operation."""
    body = self._evaluate([{"op": op, "inputs": [ct.data, str(int(scalar))]}])
    return Ciphertext(body["results"][0])
```

The SDK sends `inputs: [ciphertext_b64, str(scalar)]` with 2 elements and no `scalar` field. The Rust handler (`handlers.rs:331-358`) expects `inputs` with exactly 1 element and reads the scalar from the separate `op.scalar` JSON field:

```rust
if cts.len() != 1 { return Err("add_plain requires exactly 1 input".to_owned()); }
let scalar = op.scalar.ok_or_else(|| "add_plain requires scalar".to_owned())?;
```

This will fail at runtime with `"add_plain requires exactly 1 input"`. The correct SDK code should be:

```python
body = self._evaluate([{"op": op, "inputs": [ct.data], "scalar": int(scalar)}])
```

### FINDING 2 (Gap, Severity: High): HVT-2 (`gso_mul`) not implemented

The plan explicitly identifies `gso_mul` as a High-Value Target -- the "nine65 differentiator (depth-50 without bootstrapping)." The `handlers.rs` evaluate dispatch has no `gso_mul` arm. The `wire.rs` `Operation.op` comment (line 87) lists only `"add", "sub", "negate", "add_plain", "mul_plain", "mul"` -- no `gso_mul`. The Python SDK also has no `gso_mul` method. This is the most unique capability of NINE65 and should be prioritized.

### FINDING 3 (Gap, Severity: Medium): TrackedEvaluator (HVT-1) not used as planned

The plan states: "use [TrackedEvaluator] as session evaluator instead of raw BFVEvaluator." The `handlers.rs` comment (line 4) claims operations go "via TrackedEvaluator (HVT-1)" but the actual code constructs a raw `BFVEvaluator` (line 283) and manually calls `session.noise_budget.consume()` for each operation. While the manual tracking works and tests pass, it duplicates the cost-calculation logic that `TrackedEvaluator` already provides with `try_add()`, `try_sub()`, `try_mul()`, etc. This creates a maintenance risk where noise costs could diverge between the two implementations.

### FINDING 4 (Bug, Severity: Medium): Session ID extraction is fragile

`handlers.rs:80-88` -- `extract_session_id` uses string slicing with hard-coded prefix length:

```rust
fn extract_session_id(path: &str, suffix: &str) -> String {
    let without_suffix = &path[..path.len() - suffix.len()];
    let prefix = "/v1/sessions/";
    if without_suffix.len() > prefix.len() {
        without_suffix[prefix.len()..].to_owned()
    } else {
        String::new()
    }
}
```

If a path like `/v1/sessions//encrypt` is received, this silently returns an empty string rather than producing a clear error. More critically, there's no check that the path actually starts with `/v1/sessions/` -- the router matches on suffix only (`path.ends_with("/encrypt")`), so a request to `/something/encrypt` would match the encrypt handler with a garbage session ID.

### FINDING 5 (Correctness): NoiseBudget not consumed on encrypt

The encrypt handler (`handlers.rs:204-236`) does not call `noise_budget.consume(NoiseOpType::Encrypt, ...)`. Encryption itself adds noise -- the `NoiseBudget` module provides `encrypt_cost(config)` specifically for this purpose. While the decrypt handler similarly doesn't track noise consumption (which is correct since decrypt doesn't add noise), skipping the encrypt noise cost means the noise budget starts higher than it should relative to actual ciphertext noise.

### FINDING 6 (Correctness): Negate noise cost is hard-coded magic number

`handlers.rs:327` uses `consume(NoiseOpType::Add, 100)` with a hard-coded 100 millibits for negate. Negate is mathematically free (coefficient-wise negation in Zq) -- the noise footprint is 0. Even if a minimal cost is desired as a safeguard, it should be a named constant or method on `NoiseBudget`, not a magic number.

---

## FUNCTIONAL & SCALABILITY ANALYSIS

### Strengths

1. **Clean workspace compilation**: `cargo check --workspace --release` succeeds with only 1 fhe-service warning (`headers` field never read) and 2 clockwork-core dead-code warnings. No errors.

2. **Test coverage is solid**: 15 Rust unit tests cover the full session lifecycle, encrypt/decrypt roundtrips, homomorphic add, add_plain, noise budget tracking, max sessions enforcement, and invalid session handling. Tests use real `SecureConfig::secure_128()` keygen (not mocked) -- these are genuine FHE integration tests.

3. **Security hardening is substantially implemented**:
   - MAX_BODY_BYTES (10MB) with both content-length and in-flight guards
   - MAX_HEADER_BYTES (64KB)
   - Max connections (256, env-configurable)
   - Max sessions (64, env-configurable)
   - Wire field length validation (MAX_STRING_FIELD_LEN, MAX_CIPHERTEXT_FIELD_LEN)
   - Ciphertext validation via `from_bytes_validated(bytes, n, q)`
   - SecretKey `ZeroizeOnDrop`
   - Generic error messages to clients, details to stderr

4. **Python SDK design is clean**: Proper context manager, error hierarchy, opaque `Ciphertext` wrapper with `__slots__`, noise budget cache synchronization from server responses.

### Bottlenecks and Limitations

1. **Thread-per-connection model does not scale**: The current `main.rs` spawns `std::thread::spawn` per incoming connection. With MAX_CONNECTIONS=256, this means up to 256 OS threads, each running FHE operations that are CPU-intensive (22ms encrypt, 146ms mul for secure_128). Under load, this will saturate CPU and degrade all connections simultaneously. A bounded thread pool would be more appropriate.

2. **Write lock contention on SessionStore**: All evaluate/encrypt/decrypt operations take a write lock (`with_session_mut`) on the entire `HashMap`. If multiple clients share a server, operations on different sessions block each other. This is a coarse-grained lock -- per-session locks or a sharded map would reduce contention.

3. **No write timeout**: `main.rs:87` sets a 5-second read timeout but no write timeout. A slow-reading client could cause the response write to block indefinitely, holding a thread hostage.

4. **Session creation is expensive and synchronous**: `Session::new()` performs full keygen on the connection thread -- this takes significant time for secure configs. With many concurrent session creations, this blocks connection threads, compounding with the thread-per-connection model.

5. **No session TTL or reaper**: The plan defers "Session TTL with background reaper thread" to Phase 2, but without it, leaked sessions (client crashes, network drops) accumulate until the max_sessions limit is hit, at which point no new sessions can be created.

---

## UTILITY & DESIGN INTEGRITY

### Architecture

The microservice boundary is well-chosen. Separating PyO3 binding churn from the core workspace is a pragmatic decision that immediately unblocks development. The REST API design is clean and RESTful. The bincode-to-base64 serialization for ciphertexts is space-efficient (base64 has only 33% overhead vs raw binary in JSON).

### Module organization

The 5-module split (`main.rs`, `http.rs`, `session.rs`, `wire.rs`, `handlers.rs`) follows standard web service patterns. Each module has a clear, single responsibility. The wire types have validation methods that are called consistently in handlers.

### Integer-only mandate

The plan identifies `#![deny(clippy::float_arithmetic)]` as a **Medium** security gap for fhe-service, but this has **not been added** to the crate. While the current code appears float-free by inspection, the lint gate is not enforced. This is a one-line fix.

### Error response format mismatch

The JSON error format `{"error": {"code": "...", "message": "..."}}` is structured but inconsistent with how the Python SDK parses it. The SDK checks for `body.get("error", msg)` and `body.get("error_code")`, but the server nests `error.code` and `error.message` inside an `error` object. This means `body.get("error")` returns the entire dict object, not a string. The SDK will display something like `{'code': 'SESSION_NOT_FOUND', 'message': 'session does not exist'}` as the error message rather than extracting the human-readable message.

### Test infrastructure

The `#[cfg(test)]` gated `Session::new_test()` with deterministic seed is present but unused -- all tests use `Session::new()` with real CSPRNG keygen. This is fine for correctness testing but means tests are non-deterministic. The plan's HVT-3 (test infrastructure reuse of `test_fast()` configs) is not yet integrated.

---

## PRIORITIZED RECOMMENDATIONS

### P0 -- Must Fix (Correctness Bugs)

1. **Fix Python SDK `_eval_plain` wire format** (`session.py:128`): Change `{"op": op, "inputs": [ct.data, str(int(scalar))]}` to `{"op": op, "inputs": [ct.data], "scalar": int(scalar)}`. This is the only blocking bug for end-to-end Python SDK integration with plaintext operations.

2. **Fix Python SDK error parsing** (`client.py:80-106`): The server returns `{"error": {"code": "...", "message": "..."}}`. The SDK should extract `body["error"]["message"]` and `body["error"]["code"]`, not `body.get("error")` (which returns the nested dict) and `body.get("error_code")` (which doesn't exist at the top level).

### P1 -- High Value (Plan-stated HVTs)

3. **Implement `gso_mul` operation** (HVT-2): Add a `gso_mul` arm to the evaluate handler that wraps ciphertexts via `GSOFHEContext` for depth-50 operations. This is the primary differentiator of NINE65 and is explicitly called out as "include now." Add corresponding `gso_mul()` method to the Python SDK `Session` class.

4. **Replace manual noise tracking with `TrackedEvaluator`** (HVT-1): The current manual `noise_budget.consume()` pattern works but duplicates logic. Constructing a `TrackedEvaluator` per-request (it borrows the NTT/encoder/eval_key for the request duration) would centralize noise cost calculations and prevent drift. Alternatively, keep manual tracking but extract noise costs into constants/methods rather than inlining the `NoiseBudget::xxx_cost()` calls.

5. **Add `#![deny(clippy::float_arithmetic)]`** to `crates/fhe-service/src/main.rs` (or a `lib.rs`): One line, enforces the integer-only mandate at compile time.

### P2 -- Medium (Robustness)

6. **Add write timeout**: Set `stream.set_write_timeout(Some(Duration::from_secs(10)))` in `serve_connection` alongside the existing read timeout. Prevents slow-read client attacks.

7. **Harden path routing**: Add explicit prefix check in `extract_session_id` or restructure routing to use a proper prefix match. Currently, a request to `/anything/encrypt` with a POST will match the encrypt handler.

8. **Track encryption noise cost**: Call `noise_budget.consume(NoiseOpType::Encrypt, NoiseBudget::encrypt_cost(&session.config))` in the encrypt handler.

9. **Replace negate magic number**: Extract `100` on `handlers.rs:327` to `NoiseBudget::negate_cost()` returning 0 (or a symbolic constant).

### P3 -- Scalability (Phase 2)

10. **Replace thread-per-connection with bounded pool**: Use a bounded thread pool or work-stealing pool. This prevents unbounded thread creation and gives back-pressure under load.

11. **Per-session locks instead of global write lock**: Change `SessionStore` to `RwLock<HashMap<String, Arc<Mutex<Session>>>>` so that operations on different sessions don't block each other. The insert/remove path still takes the outer lock, but per-session operations (encrypt, evaluate, decrypt) only lock their individual session.

12. **Add session TTL reaper**: Spawn a background thread that scans `created_at` timestamps and removes sessions older than a configurable TTL (e.g., 1 hour). This prevents leaked session accumulation.

---

## RAW OBSERVATIONS

### Miscellaneous findings

- **`headers` field unused**: `http.rs:32` -- `HttpRequest.headers` is parsed but never read by any handler. The compiler warns about this. It's fine to keep it for future `x-request-id` support, but consider suppressing the warning with `#[allow(dead_code)]` and a TODO comment.

- **`unix_now_seconds()` duplicated**: Defined in both `main.rs:109` and `session.rs:36`. Extract to a shared utility or remove the one in `main.rs` (it's only used via `handlers::AppMetrics::new()` which calls `crate::unix_now_seconds()`).

- **Session creation returns 200, not 201**: REST convention is `201 Created` for resource creation. The plan's test asserts 200. Minor but worth noting for API consumers.

- **`Session::new_test()` requires secure configs only**: The plan's HVT-3 mentions using `test_fast()` configs, but `new_test()` currently only accepts the three secure configs. The dev-dependency includes `allow_insecure` but the `Session::new_test()` match arm doesn't accept light/test configs.

- **Metrics endpoint charset**: The content type should be `text/plain; version=0.0.4; charset=utf-8` per OpenMetrics spec (charset is missing).

- **No CORS headers**: If the service is to be called from browser-based clients (e.g., WASM SDK in future), CORS preflight will fail. Not needed now but worth noting for the Phase 2 WASM integration path.

- **Ciphertext size bounds**: For secure_128 (n=4096), a ciphertext is ~86KB base64. For secure_256 (n=16384), ~342KB base64. The MAX_CIPHERTEXT_FIELD_LEN of 512KB accommodates all configs. An evaluate request with the maximum 256 operations x 4 inputs x 342KB = ~350MB would exceed the 10MB MAX_BODY_BYTES, which correctly caps this at the body level before reaching operation parsing.

- **Test determinism for negate**: The Python integration test `test_negate_ciphertext` asserts `result == [-42]`. Whether negate produces -42 or `t - 42` depends on the decryption's output range convention. Verify this matches `BFVDecryptor::decrypt()` output semantics.

---

*End of audit.*
