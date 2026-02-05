# NINE65 v5 Comprehensive Audit Report

Date: 2026-02-05
Scope: NINE65 v5 workspace (code + docs + tests + CI)

## Executive Summary
- Full release test suite executed for the entire workspace with zero failures.
- Runtime tests previously marked #[ignore] are now active and pass.
- Documentation and security claims show several cross-doc conflicts that must be reconciled for a public-ready release.
- Public-mode depth behavior is implemented and tested, but baseline results are not recorded in CI artifacts.
- Serialization and validation exist for several ciphertext/key types, but coverage is incomplete for core BFV key material.

## Systematic Test Coverage (Executed)
- Command: cargo test --workspace --release
  - mana: 30 passed, 0 failed
  - nine65: 424 passed, 0 failed
  - unhal: 10 passed, 0 failed
  - Integration tests: 22 passed
  - Doc-tests: 2 passed, 39 ignored
- Command: cd lean4/KElimination && lake build
  - PASS (warnings-as-error, no deferred proofs)

See: docs/COMPREHENSIVE_TEST_REPORT_V5.md

## Scope Definition and Dependencies
Sources reviewed:
- README.md
- EXECUTION_PLAN.md
- QUESTION_MATRIX.md
- docs/ARCHITECTURE.md
- docs/SECURITY_PROOFS.md
- docs/REDSHIRT_SECURITY_ASSESSMENT.md
- docs/SECURITY_GAP_ANALYSIS.md
- docs/LATTICE_ESTIMATOR_BASELINE_2026-01-27.md
- docs/PUBLIC_MODE_DEPTH_BASELINE_2026-01-27.md
- docs/PERFORMANCE_BASELINE_2026-01-27.md
- docs/FHE_BENCHMARK_COMPARISON.md
- docs/RELEASE_CHECKLIST.md
- LICENSE
- .github/workflows/ci.yml
- fuzz/ (targets)

Defined modes and scope:
- Symmetric mode (single-party, uses secret key): deep circuits, depth-50+ claims.
- Public mode (eval-key / standard FHE): shallow by default; deeper with mod switching and retuned params.
- Secure configs: secure_128, secure_192, secure_256.
- Insecure configs (light/he_standard_128/light_rns_exact) are gated behind allow_insecure.
- Quantum modules are removed from implementation; quantum papers remain in docs/.

Security baseline references:
- Lattice estimator baseline: docs/LATTICE_ESTIMATOR_BASELINE_2026-01-27.md
- RedShirt assessment: docs/REDSHIRT_SECURITY_ASSESSMENT.md
- Security proofs (informal): docs/SECURITY_PROOFS.md

## Claims Traceability Matrix (Security / Performance / Architecture)

| Claim | Source | Evidence | Status | Notes |
| --- | --- | --- | --- | --- |
| Depth-50 without bootstrapping (symmetric) | README.md, docs/PERFORMANCE_BASELINE_2026-01-27.md | gso_fhe depth benchmarks executed | PARTIAL | Benchmarks run but do not assert correctness against a baseline threshold. |
| Public-mode depth baseline (4-5) | README.md, docs/PUBLIC_MODE_DEPTH_BASELINE_2026-01-27.md | test_public_mode_depth_sweep executed | PARTIAL | Test runs but baseline values not persisted to artifacts. |
| Post-quantum security (LWE) | README.md, docs/LATTICE_ESTIMATOR_BASELINE_2026-01-27.md | security_estimator.rs + tests | PARTIAL | Estimator exists, but outputs are not generated in CI. |
| Production-ready secure_128 | docs/ARCHITECTURE.md | params/secure_configs.rs | CONFLICT | RedShirt warns production not recommended; min N=8192 recommended. |
| Public-mode depth limited to 1 | docs/SECURITY_PROOFS.md | public-mode tests show >1 depth for some bases | CONFLICT | Docs disagree with baseline results in docs/PUBLIC_MODE_DEPTH_BASELINE_2026-01-27.md. |
| K-Elimination correctness | README.md, docs/SECURITY_PROOFS.md, Lean build | Lean build passes; many tests cover invariants | SUPPORTED | Formalization build succeeded; tests cover K-Elim paths. |
| Performance claims vs competitors | README.md, docs/FHE_BENCHMARK_COMPARISON.md | Baseline docs exist | PARTIAL | No CI gate or reproducible artifacts for external comparisons. |
| Insecure configs gated | README.md, docs/ARCHITECTURE.md, docs/SECURITY_GAP_ANALYSIS.md | allow_insecure gating in code | SUPPORTED | Claims consistent across docs and code. |

## Security Review
### Parameters and estimator
- Secure configs are defined in crates/nine65/src/params/secure_configs.rs.
- Lattice estimator logic is in crates/nine65/src/params/security_estimator.rs (integer-only).
- Baseline outputs exist in docs/LATTICE_ESTIMATOR_BASELINE_2026-01-27.md but are not tied to CI or a reproducible script.

### Side-channel posture
- README.md points to docs/REDSHIRT_SECURITY_ASSESSMENT.md for timing-side-channel notes.
- RedShirt assessment reports critical timing issues and recommends stronger parameter baselines.

### Deserialization safety
- BFV Ciphertext: validation available (from_json_validated / from_bytes_validated).
- DualRNSCiphertext: validation available with bounds checks.
- Galois keys: validated deserialize helpers exist; unvalidated deserialization is gated behind allow_insecure.
- Gap: Core BFV PublicKey/EvaluationKey serialization is not present in keys/; RNS KeySet has serde.

## Correctness Review
### Public mode depth
- Public mode depth sweep is implemented and now executed in tests.
- docs/SECURITY_PROOFS.md states public mode is depth-1 only, while docs/PUBLIC_MODE_DEPTH_BASELINE_2026-01-27.md shows depth 4-5 for some bases.
- The code includes mul_dual_public_deep with modulus switching to extend depth.

### Noise-budget tracking
- There are tracked evaluators and tracked RNS operations that return NoiseExhausted.
- Default (unchecked) operations do not enforce budgets; callers must opt-in.

## Operational Readiness
### CI
- .github/workflows/ci.yml runs build/test/clippy/rustfmt/cargo-audit/cargo-deny.
- Timing regression tests run on schedule.
- Fuzzing is not run in CI; fuzz targets exist in fuzz/.

### Release / license
- LICENSE is proprietary and prohibits redistribution; this conflicts with “public-ready” expectations for open release.
- Missing SECURITY.md and CONTRIBUTING.md.

## Documentation Coherence
- docs/ARCHITECTURE.md marks secure_128 as PRODUCTION; RedShirt recommends N=8192 high_192 and says production not recommended.
- docs/SECURITY_PROOFS.md asserts public mode depth-1 only; baseline doc shows depth 4-5 on standard_128/high_192.
- README performance comparisons are not backed by reproducible CI baselines.

## Gap Consolidation (Severity, Acceptance, Owners)

CRITICAL
1) Conflicting production-readiness claims
- Evidence: docs/ARCHITECTURE.md vs docs/REDSHIRT_SECURITY_ASSESSMENT.md
- Acceptance: single authoritative statement for production readiness, with aligned minimum secure config.
- Owner: Docs + Security
- Files: docs/ARCHITECTURE.md, docs/REDSHIRT_SECURITY_ASSESSMENT.md, README.md

HIGH
2) Public-mode depth claims inconsistent across docs
- Evidence: docs/SECURITY_PROOFS.md vs docs/PUBLIC_MODE_DEPTH_BASELINE_2026-01-27.md
- Acceptance: update SECURITY_PROOFS to reflect tested depth or document limits and required parameters.
- Owner: Crypto/Correctness + Docs
- Files: docs/SECURITY_PROOFS.md, docs/PUBLIC_MODE_DEPTH_BASELINE_2026-01-27.md, README.md

3) Side-channel mitigations incomplete
- Evidence: docs/REDSHIRT_SECURITY_ASSESSMENT.md flags timing side-channel issues.
- Acceptance: implement constant-time mitigations or explicitly scope limitations with safe defaults.
- Owner: Crypto/Implementation
- Files: crates/nine65/src/ops/, crates/nine65/src/arithmetic/, docs/REDSHIRT_SECURITY_ASSESSMENT.md

MEDIUM
4) Security estimator outputs not reproducible in CI
- Evidence: estimator exists; outputs only in docs.
- Acceptance: add a script + CI artifact (or release checklist) to generate baseline outputs.
- Owner: Security/DevOps
- Files: crates/nine65/src/params/security_estimator.rs, docs/LATTICE_ESTIMATOR_BASELINE_2026-01-27.md, .github/workflows/ci.yml

5) Performance claims not gated
- Evidence: README + docs/PERFORMANCE_BASELINE_2026-01-27.md; no CI gate.
- Acceptance: store baselines and gate at least one benchmark in CI or release checklist.
- Owner: Performance/DevOps
- Files: docs/PERFORMANCE_BASELINE_2026-01-27.md, docs/RELEASE_CHECKLIST.md, .github/workflows/ci.yml

6) Missing release security docs
- Evidence: no SECURITY.md or CONTRIBUTING.md.
- Acceptance: add SECURITY.md (reporting policy) + CONTRIBUTING.md (build/test, security notes).
- Owner: Docs/Release
- Files: SECURITY.md (new), CONTRIBUTING.md (new)

7) Serialization coverage incomplete for core BFV keys
- Evidence: Ciphertext and GaloisKey have serde; PublicKey/EvaluationKey lack serde APIs.
- Acceptance: add serde + validated deserialize helpers for BFV keys or document why not supported.
- Owner: Crypto/API
- Files: crates/nine65/src/keys/mod.rs

8) Noise budget enforcement is optional
- Evidence: tracked ops exist; unchecked ops default.
- Acceptance: add guidance or enforce budget checks in public API wrappers.
- Owner: Crypto/Correctness
- Files: crates/nine65/src/ops/homomorphic.rs, crates/nine65/src/ops/rns_fhe.rs, README.md

9) Fuzzing not wired into CI
- Evidence: fuzz targets exist; no CI step.
- Acceptance: add scheduled or nightly fuzz job with time budget.
- Owner: DevOps
- Files: fuzz/, .github/workflows/ci.yml

RESOLVED / PARTIAL
10) README examples use insecure configs
- Status: RESOLVED. README examples use SecureConfig (secure_128/secure_192). Insecure configs are explicitly gated.
- Files: README.md

## Audit Notes on Recent Fixes
- Removed all #[ignore] attributes from runtime tests to ensure full coverage.
- Fixed anchor reconstruction in diagnostic tests by using U256 reconstruction to avoid u128 overflow.
- Disabled two-stage rescale for 5-prime configs (secure_192) to preserve correctness; still enabled for >5 primes.

