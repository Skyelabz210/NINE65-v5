# Formalization Index (NINE65 v5)

This index maps formal proofs (Coq/Lean) to the Rust implementation. It is the
canonical proof-to-code reference for the v5 codebase.

## Coq proof mapping

| Proof file | Rust module(s) | Integration status |
| --- | --- | --- |
| CRTShadowEntropy.v | crates/nine65/src/entropy/crt_shadow.rs | Integrated (module docs + unit tests)
| CyclotomicPhase.v | crates/nine65/src/arithmetic/cyclotomic_phase.rs | Integrated (module docs)
| EncryptedQuantum.v | [EXCLUDED] | Quantum scope out of this build
| ExactCoefficient.v | crates/nine65/src/arithmetic/exact_coeff.rs; crates/nine65/src/arithmetic/exact_divider.rs | Integrated (module docs)
| GSOFHE.v | crates/nine65/src/ops/gso_fhe.rs; crates/nine65/src/compiler.rs | Integrated (module docs + compiler tests)
| IntegerSoftmax.v | crates/nine65/src/arithmetic/integer_softmax.rs; crates/nine65/src/ops/neural.rs | Integrated (module docs)
| KElimination.v | crates/nine65/src/arithmetic/k_elimination.rs; crates/nine65/src/ops/rns_fhe.rs | Integrated (module docs + unit tests)
| MQReLU.v | crates/nine65/src/arithmetic/mq_relu.rs | Integrated (module docs + unit tests)
| MobiusInt.v | crates/nine65/src/arithmetic/mobius_int.rs; crates/nine65/src/ops/neural.rs | Integrated (module docs)
| MontgomeryPersistent.v | crates/nine65/src/arithmetic/persistent_montgomery.rs; crates/nine65/src/arithmetic/ntt_fft.rs | Integrated (module docs)
| OrderFinding.v | crates/nine65/src/arithmetic/order_finding.rs | Integrated (module docs + unit tests)
| PadeEngine.v | crates/nine65/src/arithmetic/pade_engine.rs; crates/nine65/src/ops/neural.rs | Integrated (module docs)
| SideChannelResistance.v | crates/nine65/src/security/secret_data.rs; crates/nine65/src/arithmetic/k_elimination.rs | Integrated (module docs)
| StateCompression.v | [EXCLUDED] | Quantum state compression; out of scope for this build

## Lean proof mapping

| Lean file | Rust module(s) | Integration status |
| --- | --- | --- |
| KElimination.lean | crates/nine65/src/arithmetic/k_elimination.rs | Integrated (module docs)
| Basic.lean | crates/nine65/src/arithmetic/k_elimination.rs | Integrated (module docs)
| ZMod.lean | crates/nine65/src/arithmetic/k_elimination.rs | Integrated (module docs)
| ShadowEntropy.lean | crates/nine65/src/entropy/crt_shadow.rs | Integrated (module docs)

## Notes
- Integration status reflects documentation linkage and test coverage for the
  corresponding Rust modules.
- [GAP] entries require either a new Rust module or explicit mapping to an
  existing module when implementation becomes available.
- [EXCLUDED] entries are intentionally out of scope for this build.
- Module documentation now carries "Theorem Reference" blocks pointing to the
  relevant proof files.
