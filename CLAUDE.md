# NINE65 v5 - Claude Code Guide

## Build & Test

```bash
cargo build --release --workspace        # Build all 4 crates (nine65, nexgen_rational, mana, unhal)
cargo test --workspace --release          # Run all tests
cargo test -p nine65 --lib --release      # Core crate only
cargo test -p nine65 security::tests -- --nocapture  # Security tests
```

## Workspace Crates

| Crate | Path | Purpose |
|-------|------|---------|
| `nine65` | `crates/nine65/` | Core FHE: arithmetic, ring, ops, security, entropy, keys, noise, params |
| `mana` | `crates/mana/` | FHE stream accelerator (lane-parallel via Rayon) |
| `nexgen_rational` | `crates/nexgen_rational/` | Exact i128 rational arithmetic (zero-dep) |
| `unhal` | `crates/unhal/` | Hardware abstraction layer |

## Key Paths

- **Secure configs**: `crates/nine65/src/params/secure_configs.rs` - `SecureConfig::secure_128()`, `secure_192()`, `secure_256()`
- **Test configs**: Require `--features allow_insecure` flag
- **K-Elimination**: `crates/nine65/src/arithmetic/k_elimination.rs`
- **GSO-FHE**: `crates/nine65/src/ops/gso_fhe.rs` - Bootstrap-free depth operations
- **NTT**: `crates/nine65/src/arithmetic/ntt.rs`
- **Security estimator**: `crates/nine65/src/params/security_estimator.rs`
- **CT primitives**: `crates/nine65/src/security/secret_data.rs`
- **Rational bridge**: `crates/nine65/src/arithmetic/rational_bridge.rs` (requires `exact_rational` feature)
- **Exact noise**: `crates/nine65/src/noise/exact_noise.rs` (requires `exact_rational` feature)
- **Exact delta**: `crates/nine65/src/params/exact_params.rs` (requires `exact_rational` feature)
- **Coq proofs**: `proofs/coq/*.v` (14 proofs, requires Coq 8.18+)
- **Lean4 proofs**: `lean4/KElimination/` (4 proofs, requires Lean 4.x + Mathlib)

## Feature Flags

- `shadow-entropy` - Enable CRT shadow entropy harvester (needed for some benchmarks)
- `allow_insecure` - Enable test/light configs (NOT for production)
- `accelerated` - Link mana/unhal crates into nine65
- `v2` - Enable ntt_fft + wassan noise bundle
- `serde` - Serialization support (JSON + bincode)
- `deterministic_rng` - Reproducible testing via rand_chacha
- `exact_rational` - Enable NexGen rational bridge (exact noise tracking, BFV delta)
- `slow_tests` - Enable expensive tests
- Defaults: `ntt_fft`, `parallel` (Rayon)

## Scripts

- `scripts/generate_performance_baseline.sh` - Generates dated performance baseline in `docs/`
- `scripts/generate_security_baseline.sh` - Generates lattice estimator baseline in `docs/`

## Depth Benchmarks (ignored by default, run with --include-ignored)

```bash
cargo test -p nine65 --lib --release \
  ops::gso_fhe::depth_benchmarks::benchmark_symmetric_max_depth_secure_128 \
  -- --include-ignored --nocapture
```

## Fuzz Testing (requires nightly)

```bash
cargo +nightly fuzz run fuzz_encrypt_decrypt
cargo +nightly fuzz run fuzz_k_elimination
```

## Conventions

- Integer-only: No floating-point anywhere
- Workspace uses resolver = "2"
- Release profile: LTO fat, codegen-units=1, panic=abort
- Proprietary license
