# NINE65 v5 Comprehensive Test Report

Date: 2026-02-05
Target: NINE65 v5 (workspace)
Profile: release

## Scope
This report covers the full NINE65 v5 workspace:
- crates/nine65 (core FHE implementation)
- crates/mana (modular arithmetic accelerator)
- crates/unhal (hardware abstraction / pipeline)
- Lean formalization build for K-Elimination (lean4/KElimination)

## Test Commands Executed
1) cargo test --workspace --release
2) cd lean4/KElimination && lake build

## Results Summary
### Workspace Unit Tests (release)
- mana: 30 passed, 0 failed, 0 ignored
- nine65: 424 passed, 0 failed, 0 ignored
- unhal: 10 passed, 0 failed, 0 ignored

### Integration / Property Tests (release)
- tests/formalization_invariants.rs: 4 passed, 0 failed
- tests/random_encrypt.rs (proptest): 1 passed, 0 failed
- tests/security_integration.rs: 17 passed, 0 failed

### Doc Tests (release)
- mana: 0 passed, 1 ignored
- nine65: 2 passed, 35 ignored
- unhal: 0 passed, 3 ignored

### Formal Verification
- lean4/KElimination: lake build SUCCESS (warnings-as-error enabled; no deferred proofs)

## Previously Ignored Tests
All runtime tests/benchmarks formerly marked #[ignore] are now active and were executed in this run.

## Coverage Highlights
- Arithmetic: Barrett, Montgomery, NTT/FFT, exact division, Mobius, softmax, Pade, cyclotomic, order-finding
- RNS + K-Elimination: dual-RNS correctness, rescaling, anchor consistency, regime selection
- Encryption pipeline: keygen, encrypt/decrypt, homomorphic ops, GSO/FHE ops, noise budget tracking
- Security and invariants: HE-standard checks, parameter validation, side-channel utilities
- Integration: end-to-end FHE workflows and production configs

## Notes / Gaps
- Fuzzing (fuzz/), criterion benchmarks, and doc-tests (mostly ignored) are not executed in this run.

## Overall Status
PASS. All executed tests completed successfully in release mode with zero failures.
