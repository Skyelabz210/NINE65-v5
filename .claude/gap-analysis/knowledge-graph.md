# Gap Analysis Knowledge Graph

Cumulative findings from Codex gap analysis runs.
Each rotation adds new findings and tracks resolution status.

---

## Rotation Log

| Timestamp | Scope | Findings | Status |
|-----------|-------|----------|--------|
| 20260206T214752Z | all | 15 items | open |

---

## Rotation: 20260206T214752Z (scope: all)

Used deep-planning-audit skill (cannot emit INSIGHT_LOG/EXECUTION_PLAN here because filesystem is read-only). Findings below.

## Critical Gaps
- **Location**: `crates/nine65/src/ops/rns_fhe.rs:862-876`, `1933-1958`, `2130-2174`  
  **Issue**: `try_decrypt_auto/try_decrypt_dual` rely on `decrypt_*_with_diagnostics`, but in release builds that function returns `(value, 0)` with no margin computation, so `try_*` always returns `Ok` even when noise is exhausted.  
  **Risk**: Production deployments silently emit garbage on exhausted noise budgets; tests that pass in debug give a false sense of safety.  
  **Test Target**: Release-mode integration test that forces noise exhaustion (small Q, repeated muls) and asserts `try_decrypt_dual`/`try_decrypt_auto` return `Err` instead of decoding.

- **Location**: `crates/nine65/src/params/production.rs:20-40` and `89-103`  
  **Issue**: Two primes in `PRODUCTION_PRIMES_30BIT` (909017089, 909869057) are not ≡ 1 (mod 2·32768); `high_security()` builds a chain with them, so `validate()` fails for N=32768.  
  **Risk**: The advertised 192-bit “high_security” config is unusable (keygen/decrypt will fail or be incorrect), undermining security claims.  
  **Test Target**: Unit test asserting `ProductionConfig128::high_security().validate().unwrap()` and that every prime satisfies `(p-1) % (2*n) == 0` for n=32768.

- **Location**: `crates/nine65/src/ops/rns_fhe.rs:2360-2379` with multiplication logic at `3190-3206`  
  **Issue**: When the evaluation key has fewer limbs than the ciphertext (`evk_level < poly_level`), code silently reuses the undersized key; `zip` truncates extra ciphertext limbs, producing a malformed relinearization.  
  **Risk**: Silent wrong ciphertext values for deep circuits if eval keys aren’t regenerated after modulus switching; potential correctness failures that are hard to detect.  
  **Test Target**: Construct a ciphertext with level L and an eval key trimmed to L-1 limbs; assert relinearization errors (or returns None) rather than silently proceeding.

- **Location**: `crates/nine65/src/ops/rns_fhe.rs:441-453` (JSON validated deserialize)  
  **Issue**: Validation happens after full `serde_json` allocation; attacker-controlled array lengths can allocate unbounded memory before the MAX_* checks run.  
  **Risk**: DoS via crafted ciphertext JSON/Bincode payloads despite the claimed protections.  
  **Test Target**: Deserialization test using a deliberately oversized JSON (e.g., main limbs length 1_000_000) that must be rejected without allocating, enforced via a streaming/size-limited deserializer.

- **Location**: `crates/nine65/src/arithmetic/rns.rs:375-387` (to_int_level) and product overflow handling at `301-327`  
  **Issue**: For full chains whose modulus product exceeds u128 (e.g., 15×30-bit primes), `to_int_level` still calls `to_int` and panics instead of falling back to the U256 path; `try_to_int_level` doesn’t cover the full-level case.  
  **Risk**: Any call to `to_int_level` on production-sized chains will panic, breaking decryption/diagnostics for large parameter sets.  
  **Test Target**: Unit test building `RNSContext` with `PRODUCTION_PRIMES_30BIT` and asserting `to_int_level` gracefully errors or redirects to `to_u256_level` rather than panicking.

## Coverage Blind Spots
- **Untested Path**: Release-only branch of `decrypt_*_with_diagnostics` (margin always 0).  
  **Why It Matters**: Masks noise exhaustion in production; debug tests cannot detect.  
  **Suggested Test**: Add `--release` test that exhausts noise and asserts `try_decrypt_dual` returns `Err`.

- **Untested Path**: NTT compatibility and validation for `high_security()` (N=32768).  
  **Why It Matters**: Current prime set breaks validation; failure would surface only at runtime.  
  **Suggested Test**: New unit test for `high_security` calling `validate()` and checking `(p-1) % (2*n) == 0` for all primes and special primes.

- **Untested Path**: Relinearization with mismatched eval-key level (`evk_level < poly_level`).  
  **Why It Matters**: Silent limb truncation can corrupt results without panicking.  
  **Suggested Test**: Create ciphertext at level 3, eval key truncated to level 2, and assert the operation fails or explicitly errors.

- **Untested Path**: Overflow/`None` branch of `try_to_int_level` and U256 reconstruction.  
  **Why It Matters**: Ensures large-Q configurations don’t panic or silently wrap.  
  **Suggested Test**: Cover both overflow and non-overflow cases using 15×30-bit primes and a smaller 3-prime chain.

## Architectural Concerns
- **Pattern**: Debug/release divergence for correctness (noise diagnostics compiled out).  
  **Location**: `crates/nine65/src/ops/rns_fhe.rs:2050-2127` vs `2130-2174`.  
  **Recommendation**: Make margin computation always available (even if slower) or gate `try_*` behind a build-time feature that forbids use without diagnostics.

- **Pattern**: Silent shape coercion via iterator zipping in core arithmetic.  
  **Location**: `crates/nine65/src/ops/rns_fhe.rs:2360-2379`, `3190-3206`.  
  **Recommendation**: Enforce limb-count equality at API boundaries (return Result) and add assertions before relinearization/multiplication.

- **Pattern**: Post-parse validation instead of streamed/guarded deserialization.  
  **Location**: `crates/nine65/src/ops/rns_fhe.rs:441-453`.  
  **Recommendation**: Introduce size-limited deserializers (serde `deserialize_seq` with bounds) so allocation is bounded before validation.

## Security Surface
- **Vector**: Unbounded ciphertext deserialization (JSON/Bincode) allocating before validation.  
  **Severity**: High  
  **Mitigation**: Size-limited deserializer or pre-flight length caps; add fuzz test for oversized payload rejection.

- **Vector**: Noise exhaustion silently produces plaintext without error in release builds.  
  **Severity**: High  
  **Mitigation**: Always compute margins (or track noise budget) in release and make `try_decrypt_*` return `Err` on negative margin.

- **Vector**: Relinearization accepts lower-level eval keys without error.  
  **Severity**: Medium  
  **Mitigation**: Require level alignment and return explicit errors; add validation on key/ciphertext level before multiply.

## Priority Queue
1) Fix `try_decrypt_*` release behaviour (noise exhaustion masking) — prevents silent data corruption in production.  
2) Repair `high_security` NTT chain (primes mod 65536) — unblocks advertised 192-bit config.  
3) Enforce eval-key/ciphertext level alignment in relinearization — stops silent arithmetic corruption.  
4) Harden deserialization with pre-allocation guards — mitigates DoS from untrusted ciphertext input.  
5) Make `to_int_level` overflow-safe at full chain — prevents panics on production-sized parameter sets.

Next steps: implement the above fixes with accompanying release-mode tests; rerun `cargo test -p nine65 --release` plus new targeted cases.