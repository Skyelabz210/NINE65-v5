Now I have a comprehensive understanding of the codebase. Let me produce the audit report.

`★ Insight ─────────────────────────────────────`
This audit required deep cross-referencing between the Sonnet 4.5 system audit (the primary context), the actual source code in 7 workspace crates, and the project's stated architectural goals. The key challenge is distinguishing between findings that are genuinely novel vs. findings that restate what the prior audit already identified — since the mandate is to provide **fresh, forward-looking analysis** rather than echo existing work.
`─────────────────────────────────────────────────`

Here is the consultant audit report:

---

# CONSULTANT AUDIT

**Consultant**: Claude
**Model**: opus
**Timestamp**: 2026-02-11T02:14:28.593831
**Project**: v5

---

## EXECUTIVE SUMMARY

The NINE65 v5 comprehensive system audit produced by Sonnet 4.5 is largely accurate in its inventory and gap identification, but it under-emphasizes several **correctness and security risks** in the fhe-service boundary that could undermine production deployment more severely than the prioritization suggests. Specifically: (1) the noise budget tracking in the microservice is **decoupled from actual ciphertext noise** — it's a heuristic estimate, not a measurement, meaning the "noise exhausted" error may fire too early or too late; (2) there is a **duplicate `unix_now_seconds` function** creating dead code and potential drift; and (3) the encrypt handler **does not consume noise budget** at all, creating a tracking gap from the first operation. The core `nine65` crate remains mathematically sound and well-tested, but the microservice integration layer has subtle fidelity issues beyond the "Phase 1.5" label's implications.

---

## SYSTEM OVERVIEW

The audit under review is a comprehensive system inventory of NINE65 v5, a bootstrap-free FHE engine with a REST microservice boundary. The audit catalogs 7 workspace crates, 648 tests, feature flag dependencies, dead code, and a phased roadmap with 25 tasks totaling ~101 hours.

The audit's architectural model is sound: nine65-core is the verified cryptographic engine (41,957 LOC, 459 tests, 14 Coq proofs, 8,521 Lean4 proof lines); fhe-service is a thin HTTP boundary (~3,000 LOC, 19 tests) that wraps core operations in REST semantics with session management.

The central thesis — "core is undeniable, microservice is Phase 1.5" — is directionally correct. My analysis focuses on **what the audit missed, understated, or miscategorized** in its current plan.

---

## RIGOR & CORRECTNESS REVIEW

### Finding R1: Noise Budget Tracking is Heuristic, Not Empirical (Severity: HIGH)

The audit correctly identifies that noise budget tracking exists and works via millibits. What it fails to analyze is the **semantic gap** between the noise budget in `NoiseBudget` and the actual noise in ciphertexts.

In `crates/fhe-service/src/handlers.rs`, every evaluate operation deducts noise from `session.noise_budget` using static cost estimates (`NoiseBudget::add_cost()` returns a constant 1000 millibits, `mul_ct_cost()` uses `log2(t) + log2(N) + log2(η)`). These are **worst-case analytical bounds**, not measurements of actual ciphertext noise. This means:

1. **The budget can report exhaustion when ciphertexts are still valid** (false positive → unnecessary circuit termination)
2. **The budget can report remaining headroom when noise has actually exceeded the threshold** (false negative → silent decryption failure)

The core nine65 crate handles this correctly — GSO-FHE tracks actual basin evolution in `gso_fhe.rs`. But the fhe-service doesn't use GSO tracking; it uses the simple `NoiseBudget` estimator.

**Impact**: For production deployment, clients relying on `noise_budget_millibits` in API responses may make incorrect decisions about circuit viability.

**Recommendation**: Either (a) compute actual noise invariant from ciphertext at key operation boundaries (expensive but correct), or (b) document prominently that `noise_budget_millibits` is an upper-bound estimate, not a measurement, and rename it to `noise_budget_estimate_millibits` in the wire types.

### Finding R2: Encrypt Handler Does Not Consume Noise Budget (Severity: MEDIUM)

In `handlers.rs:194-233`, the `handle_encrypt` function calls `encryptor.encrypt_secure(v)` but **never calls `session.noise_budget.consume()`** with an encryption cost. Meanwhile, `NoiseBudget::encrypt_cost()` exists as a method but is never invoked anywhere in the fhe-service.

This means the noise budget starts at its theoretical maximum and is only decremented by evaluate operations. In practice, encryption itself adds initial noise (from the error polynomial `e` in BFV), so the budget is **over-reported** from the first operation.

**Impact**: The reported noise budget is consistently optimistic by `encrypt_cost` millibits per encrypted value.

**Recommendation**: Add `session.noise_budget.consume(NoiseOpType::Encrypt, NoiseBudget::encrypt_cost(&session.config))` to the encrypt handler for each value encrypted.

### Finding R3: Duplicate `unix_now_seconds` Function (Severity: LOW)

Two identical implementations exist:
- `crates/fhe-service/src/main.rs:111` — `pub(crate) fn unix_now_seconds()`
- `crates/fhe-service/src/session.rs:36` — `fn unix_now_seconds()` (private)

The `session.rs` version is only called within `Session::new()` and `Session::new_test()`, while `handlers.rs` calls `crate::unix_now_seconds()` (the `main.rs` version). The audit's dead code analysis (Section 4) mentions `headers` being unused but misses this duplication.

**Recommendation**: Remove the `session.rs` version and use `crate::unix_now_seconds()` consistently.

### Finding R4: `allow_insecure` Compile Guard Is Absent (Severity: HIGH)

The audit correctly identifies this in recommendation C4 and proposes a `compile_error!` guard. I verified against the codebase: **no such guard exists** in `crates/nine65/src/lib.rs` as of this review. The `forbid(unsafe_code)` is present but the insecure feature guard is not.

The current mitigation is that `fhe-service/Cargo.toml` only enables `allow_insecure` in `[dev-dependencies]`, which is correct. But nothing prevents a downstream consumer from enabling it in release builds.

**Concurrence**: The audit's C4 recommendation is correct and should be implemented immediately. It is a 30-second change with high safety value.

### Finding R5: Noise Budget Does Not Account for Rescaling in fhe-service `mul` (Severity: MEDIUM)

In `handlers.rs:369-393`, the `mul` operation consumes both `mul_ct_cost` and `relin_cost`, but does **not** apply `rescale_cost` (which is negative — a budget gain). The core evaluator calls `mul_no_relin + relinearize`, but it's unclear whether rescaling (K-Elimination) is applied in this path. If it is, the budget tracker is pessimistic (doesn't credit the rescale gain). If it isn't, then deep circuits through the REST API are noisier than through the core API.

**Recommendation**: Audit whether `BFVEvaluator::mul_no_relin + relinearize` performs K-Elimination rescaling. If yes, add the corresponding negative noise consumption. If no, this is a functional gap — the REST path produces noisier ciphertexts than the direct core API.

---

## FUNCTIONAL & SCALABILITY ANALYSIS

### Finding F1: Thread-Per-Connection Model Won't Scale (Severity: MEDIUM-HIGH)

The fhe-service uses `std::thread::spawn` for each incoming TCP connection (`main.rs:76`). With FHE operations taking 22ms–444ms per operation (from the benchmark table), and sessions holding ~200MB of key material, this model has severe limitations:

- **256 concurrent connections** × ~200MB key material per session = ~50GB memory at peak
- Thread stack overhead: 256 threads × 8MB default stack = 2GB just for stacks
- No connection reuse (HTTP/1.1 with `Connection: close`)

The `AtomicUsize` connection limiter at 256 is a reasonable stop-gap, but the architecture fundamentally cannot serve high-throughput workloads.

**Recommendation**: The audit's roadmap should include migrating to an async runtime (tokio) or at minimum a thread pool with work-stealing. This is more impactful than several of the listed MEDIUM priorities.

### Finding F2: Session Keygen Is Synchronous and Blocking (Severity: MEDIUM)

`Session::new()` performs full keygen (KeySet::generate_secure) during the HTTP request handler. For `secure_256`, this involves N=16384 with 7+ primes, which is expensive. The caller holds no lock during keygen, but the response is blocked until keygen completes.

**Impact**: Creating a `secure_256` session likely takes several seconds, during which the HTTP thread is completely occupied.

**Recommendation**: Consider async keygen or a session creation queue. The audit's H4 recommendation (expose `secure_128_deep`) is correctly scoped but doesn't address the latency of session creation itself.

### Finding F3: RwLock Contention on SessionStore (Severity: MEDIUM)

The `SessionStore` uses a single `RwLock<HashMap<String, Session>>`. Any evaluate or encrypt operation takes a **write lock** on the entire map (via `with_session_mut`), even though it only mutates one session. This serializes all write operations across all sessions.

The audit mentions this in H7 (concurrent session throughput benchmark) but categorizes it as a benchmarking task rather than an architectural bottleneck.

**Recommendation**: Replace with a concurrent map (dashmap) or per-session RwLock to allow concurrent operations on different sessions. This is prerequisite for meaningful concurrent throughput.

### Finding F4: Galois Implementation Is Correct but Incomplete for Production Rotation

I verified the Galois implementation in `galois.rs`. The automorphism logic is mathematically correct:
- Generator selection (5 for power-of-2 N) is standard
- Reduction mod (X^N + 1) handles sign flipping correctly
- Key switching decomposition is properly implemented
- Thread safety assertions are compile-time verified

However, the implementation generates rotation keys **for all rotations 1..max_rotation linearly**. For large N (e.g., N=4096, max slots = 2048), this means generating up to 2048 key-switching matrices, each containing `ceil(64/decomp_bits)` polynomial pairs. At 8-bit decomposition, that's 8 × 2 × 4096 × 8 bytes × 2048 rotations ≈ **1GB of key material**.

**Recommendation**: Implement logarithmic rotation key generation (powers of 2 only: rotations by 1, 2, 4, 8, ...) and compose arbitrary rotations from these. This reduces key material from O(N) to O(log N) keys — standard practice in SEAL, OpenFHE, and HElib.

---

## UTILITY & DESIGN INTEGRITY

### Finding U1: Audit Roadmap Effort Estimates Are Plausible but Load-Bearing

The phased rollout (Phase 1.5 → 2.0 → 2.5 → 3.0) with ~101 total hours is reasonable for a single experienced developer. However:

- **C1 (Session TTL)** at 6 hours is accurate for implementation but ignores integration testing with long-running clients
- **H1 (Galois Rotations)** at 10 hours understates the logarithmic key generation optimization needed (Finding F4)
- **H7 (Concurrent Throughput)** at 3 hours assumes the current architecture can be benchmarked meaningfully — it can't without the RwLock fix (Finding F3)

### Finding U2: Python SDK Exists but Is Unmentioned in the Audit

The audit inventories 7 workspace crates but does not mention the Python SDK at `sdks/python/`. This SDK (`nine65_sdk`) includes a client, session manager, ciphertext wrapper, and a roundtrip test. It is a consumer of the fhe-service REST API and should be validated against any wire type changes (H1, H2).

**Recommendation**: Add the Python SDK to the integration test matrix. Any wire protocol changes (batch_mode, rotate operations) will break existing SDK consumers.

### Finding U3: Error Message Security Is Well-Handled

The test `encrypt_error_does_not_leak_plaintext_modulus` (`main.rs:562-589`) demonstrates good security discipline — error messages don't leak the plaintext modulus `t`. This pattern should be extended to all new endpoints (rotation, batch operations).

### Finding U4: Metrics Endpoint Already Exists (Audit Mismatch)

The audit lists "Health Endpoint Enrichment" as C5 and "Metrics Endpoint" as M4, but the codebase already has a Prometheus-format `/v1/metrics` endpoint (`handlers.rs:117-143`) with `fhe_requests_total`, `fhe_requests_failed_total`, `fhe_active_sessions`, and `fhe_uptime_seconds`. The audit's C5 is partially obsoleted by existing code.

**Recommendation**: Reclassify C5 — the basic metrics endpoint exists. What's missing is per-session noise budget percentiles and memory usage, which is a smaller scope than suggested.

---

## PRIORITIZED RECOMMENDATIONS

Ordered by impact × urgency:

### 1. **CRITICAL: Add `allow_insecure` compile guard** (30 minutes)
The audit's C4 — add `compile_error!` in `lib.rs`. Prevents catastrophic misconfiguration.

### 2. **CRITICAL: Fix encrypt noise budget tracking** (1 hour)
Add `noise_budget.consume(Encrypt, ...)` to the encrypt handler. Current behavior over-reports available noise budget.

### 3. **HIGH: Replace SessionStore RwLock with per-session locking** (4 hours)
Unblocks concurrent session throughput. Pre-requisite for H7 benchmark having any value.

### 4. **HIGH: Implement Session TTL + Reaper** (6 hours)
The audit's C1. Memory exhaustion attack vector is real.

### 5. **HIGH: Implement logarithmic rotation key generation** (4 hours)
Before wiring Galois to fhe-service (H1), optimize key generation from O(N) to O(log N) keys. Without this, a single session with full rotation support at N=4096 will consume ~1GB RAM for keys alone.

### 6. **HIGH: Document noise budget as estimate, not measurement** (2 hours)
Rename wire field, add documentation. Prevents incorrect client decisions about circuit viability.

### 7. **MEDIUM: Wire Galois rotation endpoint** (8 hours after #5)
The audit's H1, but scoped to logarithmic keys only.

### 8. **MEDIUM: Integrate ParallelEncryptor** (2 hours)
The audit's H3. Simple refactor with immediate throughput gains.

### 9. **MEDIUM: Add `secure_128_deep` to session creation** (30 minutes)
The audit's H4. Trivial change.

### 10. **LOW: Migrate to async runtime or thread pool** (16 hours)
Long-term scalability. Not urgent for initial deployment with connection limits, but the thread-per-connection model is a ceiling.

---

## RAW OBSERVATIONS

1. **`session.rs:36` vs `main.rs:111`**: Two implementations of `unix_now_seconds`. The `session.rs` version is private and called only from `Session::new()` / `Session::new_test()`. The `main.rs` version is `pub(crate)`. The `session.rs` version should import from `crate::unix_now_seconds()`.

2. **Noise accounting gap**: The `handle_encrypt` function increments `session.operation_count` but does not consume noise budget. The `handle_evaluate` function does both. This asymmetry means the noise history (`operations()` log) is incomplete — encrypt operations are invisible to noise tracking.

3. **`GaloisKey::validate()` uses `is_multiple_of(2)`**: This is `usize::is_multiple_of`, which is a nightly-only API as of stable Rust 1.73. If the project compiles on stable, this may be using an unstable feature or a trait extension. Worth verifying.

4. **Ciphertext validation on deserialization**: `ct_from_b64` calls `Ciphertext::from_bytes_validated(&bytes, self.config.n, self.config.q)`, which is good security practice. This same pattern should be enforced for any future Galois key deserialization from wire.

5. **`unwrap_or_else(|e| e.into_inner())`** pattern on `RwLock` (session.rs:177, 191, 200, 211): This ignores lock poisoning by recovering the inner data. This is intentional (a panic in one session handler shouldn't poison the entire store), but it means **panics are silently recovered from**, potentially leaving sessions in inconsistent state. Document this as an explicit design choice.

6. **Base64 encoding overhead**: Each ciphertext for N=4096 with 3 primes is ~100KB in bincode, expanding to ~133KB in base64. For batch operations (1024 values), the JSON payload could reach ~130MB — close to the 10MB body limit. The limit should be verified against actual payload sizes for maximum batch + maximum polynomial size.

7. **The audit's test count (648) conflicts with README (640)**: The CURRENT_CONTEXT says 648, README says 640. The discrepancy is likely due to the fhe-service tests (19) being counted inconsistently. This should be reconciled for credibility.

8. **`exact_transcendentals` crate appears in the audit but not in `Cargo.toml` workspace members**: The workspace uses `members = ["crates/*"]` which would include it if present. Verify its location.

9. **`Connection: close` in HTTP responses**: The server sends `Connection: close` on every response (`http.rs:151`), forcing a new TCP connection per request. For clients making multiple operations (encrypt → evaluate → decrypt), this triples connection overhead. HTTP keep-alive would be a simple win.

10. **No TLS**: The TCP listener binds to plaintext HTTP. For production deployment where secret keys reside server-side, the network path should be encrypted. The audit doesn't mention TLS at all — it should be a CRITICAL item for any deployment beyond localhost.

---

*End of Consultant Audit*

`★ Insight ─────────────────────────────────────`
- **Noise budget fidelity**: The gap between *estimated* and *actual* noise is a common pitfall in FHE service layers. Microsoft SEAL solves this by computing `invariant_noise_degree` directly from the ciphertext — expensive but correct. NINE65's GSO-FHE does basin tracking internally, but this isn't plumbed through to the REST boundary.
- **O(N) vs O(log N) rotation keys**: This is a well-known optimization. SEAL's `GaloisKeys` generates only for specific rotation steps; HElib uses the "baby-step giant-step" hoisting pattern. The current linear generation would be the single largest memory consumer in a Galois-enabled session.
- **Lock granularity matters more than benchmarking**: The audit's H7 (concurrent throughput benchmark) would measure the RwLock contention problem, not the actual FHE throughput. Fixing the lock architecture first (per-session or concurrent map) means the benchmark measures what it should measure.
`─────────────────────────────────────────────────`
