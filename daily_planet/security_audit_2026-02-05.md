# NINE65 v5 FHE Security Audit Report

**Auditor**: Red Team Security Analysis (Claude Opus 4.5)
**Date**: 2026-02-05
**Scope**: NINE65 v5 Proofstack - Comprehensive FHE System Review
**Classification**: INTERNAL - Security Assessment

---

## Executive Summary

The NINE65 v5 FHE (Fully Homomorphic Encryption) system demonstrates a mature security posture with well-designed cryptographic primitives, formal verification coverage in Coq/Lean4, and defense-in-depth practices. The codebase shows evidence of a December 2024 cryptographic audit with subsequent hardening.

**Overall Security Assessment: STRONG with noted gaps**

| Category | Status | Notes |
|----------|--------|-------|
| Cryptographic Primitives | GOOD | Constant-time operations, proper entropy sources |
| Formal Proofs | PARTIAL | Some critical theorems admitted, not fully proven |
| Side-Channel Resistance | GOOD | Mathematical proofs present; implementation needs runtime verification |
| Parameter Security | STRONG | HE Standard v1.1 compliant, proper security estimation |
| Key Management | STRONG | Zeroize-on-drop, CSPRNG for production |
| Entropy/Randomness | GOOD | Clear separation of CSPRNG vs deterministic paths |

---

## Critical Findings

**No critical vulnerabilities identified.**

The system has no immediately exploitable critical vulnerabilities. All cryptographic operations use appropriate primitives, and the attack surface is well-controlled.

---

## High Priority Issues

### H-01: Admitted Proofs in Coq Formal Verification

**Severity**: HIGH
**Location**: `/home/user/NINE65-v5-proofstack/proofs/coq/`
**Impact**: Mathematical correctness guarantees are incomplete

**Description**:

Several critical theorems in the Coq proofs are marked as `Admitted` rather than fully proven:

```
proofs/coq/KElimination.v:530   - incremental_crt_sound
proofs/coq/KElimination.v:618   - m_level_inv_exists
proofs/coq/KElimination.v:667   - signed_k_range
proofs/coq/CyclotomicPhase.v:165 - modular arithmetic lemmas
proofs/coq/OrderFinding.v:488   - order finding theorem
proofs/coq/StateCompression.v:138,176 - exponential bounds
```

**Risk Analysis**:
- The K-Elimination soundness proof (`incremental_crt_sound`) is foundational to the exact division guarantee
- If these admitted lemmas are false, the entire RNS reconstruction could produce incorrect results
- The `m_level_inv_exists` lemma is critical for rescaling operations

**Recommendation**:
1. Prioritize completing the `incremental_crt_sound` proof
2. Add runtime assertions that validate admitted invariants
3. Consider fuzzing campaigns specifically targeting the admitted mathematical properties
4. Document which admitted lemmas are "well-known facts" vs. novel claims

---

### H-02: Shadow Entropy Used in EvaluationKey::generate_secure()

**Severity**: HIGH
**Location**: `/home/user/NINE65-v5-proofstack/crates/nine65/src/keys/mod.rs:239-240`
**Impact**: Evaluation key generation may have reduced entropy

**Description**:

```rust
pub fn generate_secure(/* ... */) -> Self {
    let mut harvester = ShadowHarvester::from_os_seed();  // Line 239
    Self::generate(sk, config, ntt, &mut harvester)       // Line 240
}
```

While `from_os_seed()` uses OS CSPRNG for the seed, the subsequent random values come from the LFSR+counter Shadow Entropy generator. This is a deterministic PRNG, not a CSPRNG.

**Risk Analysis**:
- Shadow Entropy passes NIST SP 800-22 statistical tests but is not cryptographically secure
- An attacker who can observe some outputs may be able to predict future outputs
- Evaluation keys contain information about s^2 (secret key squared)

**Recommendation**:
1. Use full `secure_*` functions from `entropy/secure.rs` for all EvaluationKey generation
2. Or document in security notes that eval key noise uses deterministic PRNG with OS seed

---

## Medium Priority Issues

### M-01: Variable-Time Barrett Reduction in Default Path

**Severity**: MEDIUM
**Location**: `/home/user/NINE65-v5-proofstack/crates/nine65/src/arithmetic/barrett.rs:58-80`
**Impact**: Potential timing side-channel

**Description**:

The default `reduce()` function uses early return and conditional branches:

```rust
pub fn reduce(&self, a: u128) -> u64 {
    if a < self.q as u128 {
        return a as u64;  // Early exit - timing leak
    }
    // ...
    if result >= self.q {    // Data-dependent branch
        result -= self.q;
    }
    if result >= self.q {    // Data-dependent branch
        result -= self.q;
    }
    result
}
```

A constant-time version `reduce_ct()` exists but is not the default.

**Recommendation**:
1. Make `reduce_ct()` the default implementation
2. Rename variable-time version to `reduce_vartime()` with deprecation warning
3. Audit all call sites to ensure CT version is used for secret data

---

### M-02: Deprecated Unvalidated Deserialization Available

**Severity**: MEDIUM
**Location**: `/home/user/NINE65-v5-proofstack/crates/nine65/src/keys/mod.rs:350-363, 405-419`
**Impact**: Potential DoS or type confusion if used incorrectly

**Description**:

Unvalidated deserialization methods exist behind feature flags:

```rust
#[cfg(all(feature = "serde", feature = "allow_insecure"))]
#[deprecated(since = "0.1.0", note = "Use from_json_validated() for untrusted input")]
pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
    serde_json::from_str(s)
}
```

While deprecated and behind feature gates, the methods can still be used.

**Recommendation**:
1. Add `#[doc(hidden)]` to prevent documentation visibility
2. Consider removing entirely in a future major version
3. Add compile-time warning if `allow_insecure` feature is enabled in release builds

---

### M-03: Variable-Time Exponentiation Used for NTT Roots

**Severity**: MEDIUM
**Location**: `/home/user/NINE65-v5-proofstack/crates/nine65/src/arithmetic/montgomery.rs:184-202`
**Impact**: NTT root computation has timing side-channels

**Description**:

```rust
pub fn montgomery_pow_vartime(&self, base: u64, exp: u64) -> u64 {
    // ...
    while e > 0 {
        if e & 1 == 1 {  // Data-dependent branch on exponent
            result = self.montgomery_mul(result, base);
        }
        // ...
    }
}
```

This is explicitly documented as variable-time, but if used with secret exponents, it would leak information.

**Risk Analysis**:
- NTT roots use public exponents, so this is acceptable
- However, the function could be misused with secret exponents

**Recommendation**:
1. Add `#[doc(cfg(feature = "secret_exponent_unsafe"))]` or similar marker
2. Consider renaming to `montgomery_pow_public_exponent()`
3. Add debug assertion that exponent is from public parameter set

---

### M-04: Side-Channel Proofs are Mathematical Only

**Severity**: MEDIUM
**Location**: `/home/user/NINE65-v5-proofstack/proofs/coq/SideChannelResistance.v`
**Impact**: Implementation may not match proven model

**Description**:

The Coq proofs establish mathematical constant-time properties using an abstract cost model:

```coq
Definition cost_mod : Cost := 1.
Definition cost_add : Cost := 1.
Definition cost_mul : Cost := 1.
```

However, as noted in the proof file itself (lines 417-424):
- Compiler optimizations may reintroduce branches
- Hardware implementation details not captured
- Microarchitectural effects not modeled

**Recommendation**:
1. Use tools like `ct-verif`, `timecop`, or `dudect` to verify actual implementation timing
2. Compile with `-C opt-level=0` or use `#[inline(never)]` for constant-time-critical functions
3. Consider using assembly intrinsics for the most critical paths (Montgomery reduction, conditional select)
4. Add CI job that runs timing verification on each commit

---

### M-05: CBD Sampling in Secure Path Uses Individual CSPRNG Calls

**Severity**: MEDIUM
**Location**: `/home/user/NINE65-v5-proofstack/crates/nine65/src/entropy/secure.rs:190-203`
**Impact**: Performance and potential bias

**Description**:

```rust
pub fn secure_cbd(eta: usize) -> i64 {
    let mut sum = 0i64;
    for _ in 0..eta {
        let bits = secure_u64();  // Full CSPRNG call per iteration
        let a = (bits & 1) as i64;
        let b = ((bits >> 1) & 1) as i64;
        sum += a - b;
    }
    sum
}
```

Each eta iteration calls `secure_u64()` but only uses 2 bits, wasting 62 bits of entropy per call.

**Recommendation**:
1. Buffer entropy and extract multiple CBD samples from a single CSPRNG call
2. For eta=3 with N=4096 polynomials, this would reduce CSPRNG calls from 12288 to ~192

---

## Low Priority Issues

### L-01: Division Timing in K-Elimination Final Step

**Severity**: LOW
**Location**: `/home/user/NINE65-v5-proofstack/crates/nine65/src/arithmetic/k_elimination.rs:374-381`
**Impact**: Minor timing variation based on divisor

**Description**:

```rust
pub fn exact_divide(&self, v_alpha: u128, v_beta: u128, divisor: u64) -> u128 {
    let k = self.extract_k(v_alpha, v_beta);  // CT
    let v_full = v_alpha + k * self.alpha_cap;
    v_full / (divisor as u128)  // Hardware division - timing varies
}
```

While `extract_k()` is constant-time, the final division uses hardware division which may have data-dependent timing.

**Risk Analysis**:
- In FHE rescaling, the divisor is typically a public modulus
- The full value is secret, but hardware division timing typically depends on operand sizes, not values
- Low practical risk

**Recommendation**:
1. Document that divisor should be public
2. Consider constant-time division for paranoid security mode

---

### L-02: Test Configurations Available Outside Test Builds

**Severity**: LOW
**Location**: `/home/user/NINE65-v5-proofstack/crates/nine65/src/params/secure_configs.rs:215-241`
**Impact**: Insecure configs could theoretically be used if misconfigured

**Description**:

```rust
#[cfg(any(test, debug_assertions))]
pub fn test_fast() -> Self { /* 40-bit security */ }
```

Test configs are properly gated behind `cfg`, but `debug_assertions` is true in debug builds which may be deployed in some environments.

**Recommendation**:
1. Consider `#[cfg(test)]` only for truly test-only configs
2. Add runtime check in `test_fast()` that panics if `NINE65_ALLOW_INSECURE` env var is not set

---

### L-03: Ternary Distribution Rejection Rate

**Severity**: LOW
**Location**: `/home/user/NINE65-v5-proofstack/crates/nine65/src/entropy/secure.rs:174-183`
**Impact**: Minor performance variation

**Description**:

```rust
pub fn secure_ternary() -> i64 {
    loop {
        let r = secure_u64() % 4;  // 0, 1, 2, 3
        if r < 3 {
            return (r as i64) - 1;
        }
        // 25% rejection rate
    }
}
```

The rejection rate is 25%, which is acceptable but could cause timing variations.

**Recommendation**:
1. Consider using Fisher-Yates-like sampling from 3 values with larger buffers
2. Or document that ternary sampling has slight timing variation (not exploitable)

---

## Security Controls Assessment

### Positive Findings

1. **Zeroize Implementation**: SecretKey implements `ZeroizeOnDrop` correctly using the `zeroize` crate. This prevents secret key material from lingering in memory.

2. **Constant-Time K-Elimination**: The default `extract_k()` method is now constant-time with 128 fixed iterations:
   ```rust
   fn mul_mod_u128_ct(a: u128, b: u128, m: u128) -> u128 {
       // Fixed 128 iterations for constant-time
       for i in 0..128 { ... }
   }
   ```

3. **Montgomery Ladder for Secret Exponents**: The `montgomery_pow()` function uses proper constant-time Montgomery ladder with XOR-based conditional swap.

4. **Validated Deserialization**: All public deserialization methods require validation:
   ```rust
   pub fn from_json_validated(s: &str, expected_n: usize, expected_q: u64) -> Nine65Result<Self>
   ```

5. **Production Safety Guard**: The `ProductionSafe` trait prevents use of weak configs in release builds.

6. **OS CSPRNG for Secret Keys**: `SecretKey::generate_secure()` properly uses `getrandom` for OS entropy.

7. **Coprimality Validation**: K-Elimination constructor validates that alpha and beta moduli are coprime:
   ```rust
   pub fn try_new(alpha_primes: &[u64], beta_primes: &[u64]) -> Nine65Result<Self>
   ```

---

## Formal Proof Coverage Matrix

| Component | Coq Proof Status | Key Theorems |
|-----------|------------------|--------------|
| K-Elimination Core | PROVEN | `k_elimination_complete`, `kElimination_unique` |
| K-Elimination Soundness | ADMITTED | `incremental_crt_sound` |
| Montgomery Reduction | PROVEN | `montgomery_reduce_correct` |
| Side-Channel Properties | PROVEN | `nine65_side_channel_secure` |
| Signed-K Range | ADMITTED | `signed_k_range` |
| M-Level Inverse Existence | ADMITTED | `m_level_inv_exists` |
| GSO-FHE Noise Bounds | PARTIAL | `collapse_soundness_bound` |
| MQ-ReLU Sign Detection | PROVEN | (in MQReLU.v) |

---

## Risk Register

| ID | Risk | Likelihood | Impact | Priority | Status |
|----|------|------------|--------|----------|--------|
| H-01 | Admitted proofs may be incorrect | Low | High | HIGH | Open |
| H-02 | Shadow Entropy in eval keys | Medium | Medium | HIGH | Open |
| M-01 | Variable-time Barrett default | Medium | Low | MEDIUM | Open |
| M-02 | Deprecated insecure deserialize | Low | Medium | MEDIUM | Open |
| M-03 | Vartime exponent misuse | Low | Medium | MEDIUM | Mitigated (documented) |
| M-04 | CT proofs not verified on impl | Medium | Medium | MEDIUM | Open |
| M-05 | Inefficient CBD sampling | High | Very Low | MEDIUM | Open |

---

## Remediation Roadmap

### Phase 1: Immediate (1-2 weeks)
1. [ ] Complete `incremental_crt_sound` proof or add runtime validation
2. [ ] Change `EvaluationKey::generate_secure()` to use full CSPRNG
3. [ ] Make `reduce_ct()` the default Barrett reduction

### Phase 2: Short-term (1 month)
4. [ ] Run `dudect` or similar timing verification on constant-time functions
5. [ ] Add CI job for timing regression tests
6. [ ] Optimize CBD sampling to use entropy more efficiently
7. [ ] Complete remaining admitted proofs or document why they are sound

### Phase 3: Medium-term (3 months)
8. [ ] Consider assembly implementations for critical CT paths
9. [ ] Add formal verification of Rust implementation against Coq specs
10. [ ] External cryptographic audit of full system

---

## Test Coverage Gaps

1. **No timing tests in CI**: While constant-time code is present, no automated timing verification
2. **Fuzz testing scope limited**: Only encrypt/decrypt roundtrip is fuzzed
3. **Missing fuzz targets**:
   - K-Elimination edge cases (values near capacity)
   - RNS reconstruction with adversarial inputs
   - NTT with malformed polynomials
   - Key deserialization with malicious payloads

---

## Conclusion

The NINE65 v5 FHE system demonstrates strong security engineering with appropriate use of constant-time operations, proper entropy separation, and formal verification. The main gaps are:

1. **Proof Completeness**: Several critical Coq theorems are admitted
2. **Implementation Verification**: CT proofs are mathematical; runtime verification needed
3. **Entropy Consistency**: EvaluationKey secure path uses Shadow Entropy

With the recommended remediations, the system would be suitable for production deployment in applications requiring 128-bit post-quantum lattice security.

---

**Audit Session**: https://claude.ai/code/session_01FZBpUkWatAnvxYLFEQQDef
**Report Generated**: 2026-02-05
**Next Review Recommended**: 2026-05-05 (90 days)
