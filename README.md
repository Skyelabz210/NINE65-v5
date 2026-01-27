# NINE65 - Bootstrap-Free Fully Homomorphic Encryption

**High-performance FHE achieving depth-50 without bootstrapping (symmetric mode)**

---

## Executive Summary

| Metric | NINE65 | Traditional FHE |
|--------|--------|-----------------|
| **Max Depth** | 50+ levels (symmetric) | 10-15 levels |
| **Bootstrap Required** | Never | Every ~10 muls |
| **Depth-50 Circuit** | 812ms (symmetric) | 2,000-5,000ms |
| **Memory** | ~200MB | 1-3GB |
| **Hardware** | CPU only | GPU recommended |
| **Post-Quantum** | Rough LWE baseline in docs/LATTICE_ESTIMATOR_BASELINE_2026-01-27.md | Varies |

Public-mode depth baseline is recorded in docs/PUBLIC_MODE_DEPTH_BASELINE_2026-01-27.md.

---

## Post-Quantum Security

NINE65 targets post-quantum security through LWE (Learning With Errors) based cryptography:

### Lattice Estimator Baseline (2026-01-27)
Rough LWE estimates (Core-SVP + GSA) for SecureConfig parameters are recorded in
docs/LATTICE_ESTIMATOR_BASELINE_2026-01-27.md.

| SecureConfig | n | log2(q) | min attack log2(rop) |
|--------------|---|---------|----------------------|
| `secure_128` | 4096 | 89.26 | 123.6 |
| `secure_192` | 8192 | 145.39 | 165.6 |
| `secure_256` | 16384 | 203.81 | 268.1 |

Notes:
- These are rough estimates, not formal security proofs.
- Test-only configs (`light`, `he_standard_128`, `light_rns_exact`) require `allow_insecure`.

### Self-Cryptanalysis

This repository includes security analysis tools in `src/security/`:
- Attack cost estimator (Primal, Dual, Hybrid, HE Standard)
- K-Elimination specific attack analysis
- LLL/BKZ lattice attack simulations

Timing side-channel posture and parameter warnings are documented in
docs/REDSHIRT_SECURITY_ASSESSMENT.md.

### Why LWE is Quantum-Resistant
- **Lattice-based hardness**: Security relies on the hardness of lattice problems
- **No known quantum speedup**: Unlike RSA/ECC, Shor's algorithm doesn't break LWE
- **NIST PQC finalist**: LWE-based schemes selected for post-quantum standardization

### Verification
```bash
# Run security parameter tests
cargo test -p nine65 security::tests -- --nocapture
```

**Note**: These are parameter estimates based on standard LWE security analysis.
For formal guarantees, external audits and independent estimator runs are recommended.
Baseline estimator outputs are recorded in docs/LATTICE_ESTIMATOR_BASELINE_2026-01-27.md.

---

## Public Mode Depth Baseline (2026-01-27)

Public-key (eval-key) mode is depth-limited relative to symmetric mode. The depth sweep
baseline is recorded in docs/PUBLIC_MODE_DEPTH_BASELINE_2026-01-27.md.

Summary:
- `standard_128`: max depth 4 at bases 2^16/2^12/2^10; max depth 5 at base 2^8
- `high_192`: max depth 4 at bases 2^16/2^12/2^10/2^8

For deeper public-mode circuits, use symmetric mode or modulus switching with retuned
parameters and re-run the depth sweep.

---

## Key Innovations

### 1. K-Elimination (Exact Division in RNS)
Traditional RNS cannot divide. K-Elimination solves the 70-year-old problem:
- **Dual-track architecture**: Main moduli + anchor moduli
- **Exact rescaling**: No floating-point, no approximation errors
- **O(k) complexity**: Linear in number of RNS lanes

### 2. GSO-FHE (Gravitational Swarm Optimization)
Noise bounding without bootstrapping:
- **Basin tracking**: Monitor noise evolution per coefficient
- **Gravitational collapse**: Controlled noise reduction when needed
- **Zero bootstrap operations** at depth-50

### 3. CRT Shadow Entropy
Cryptographic entropy harvested from modular arithmetic:
- **QuotientSignature**: O(1) magnitude comparison without reconstruction
- **8.9M ops/sec** entropy generation
- **284 Mbit/s** entropy rate

### 4. Non-Circular Order Finding
Classical period finding without circular dependencies:
- **BSGS with B=N-1**: No φ(N) computation required
- **K-Elimination verification**: Winding number oracle
- **Shor's classical reduction**: Complete factoring via gcd(a^(r/2) ± 1, N)

---

## Performance Benchmarks

Performance numbers are from internal release benchmarks. Reproduce and gate via
docs/RELEASE_CHECKLIST.md.

### Arithmetic Operations (Single-threaded, Release Build)

#### RNS Arithmetic (4-lane parallel)
| Operation | Time/op | Throughput |
|-----------|---------|------------|
| ADD | 48 ns | 20.7M ops/sec |
| SUB | 41 ns | 24.3M ops/sec |
| MUL | 83 ns | 12.0M ops/sec |
| MUL+Signature | 101 ns | 9.9M ops/sec |

#### Exact Coefficient Arithmetic (Dual-Track)
| Operation | Time/op | Throughput |
|-----------|---------|------------|
| COEFF_ADD | 52 ns | 19.1M ops/sec |
| COEFF_MUL | 70 ns | 14.3M ops/sec |
| COEFF_DIV | 48 ns | 20.7M ops/sec |
| COEFF_SCALE | 49 ns | 20.4M ops/sec |

#### FHE Operations
| Operation | Time | Notes |
|-----------|------|-------|
| Encrypt | <1ms | 80x faster than traditional |
| Add | ~50us | Real-time capable |
| Mul | ~16ms | Including K-Elimination rescale |
| Depth-50 Circuit | 812ms | Zero bootstraps |

### Depth Benchmark Results
```
Depth: 50 multiplicative levels
Basin collapses: 0
Total time: 812ms
Average per mul: 16.24ms
Bootstraps required: 0
```

---

## Comparison vs Industry Leaders

Methodology and sources are documented in docs/FHE_BENCHMARK_COMPARISON.md.

```
Library          | Max Depth | Bootstrap | Depth-50 Time
-----------------+-----------+-----------+--------------
NINE65           |    50+    |   Never   |    812ms
OpenFHE (BGV)    |    15     |   ~50ms   |   ~2,500ms
Microsoft SEAL   |    12     |    N/A    |   (limited)
TFHE-rs (GPU)    | Unlimited |   <1ms    |    ~200ms*
HElib            |    12     |  ~100ms   |   ~5,000ms

* Requires $30k+ GPU (H100)
```

---

## Architecture

```
NINE65/MANA_boosted/
├── crates/
│   ├── nine65/           # Core FHE implementation
│   │   └── src/
│   │       ├── arithmetic/
│   │       │   ├── rns.rs              # Dual-RNS with K-Elimination
│   │       │   ├── exact_coeff.rs      # Exact coefficient arithmetic
│   │       │   ├── exact_divider.rs    # K-Elimination division
│   │       │   └── order_finding.rs    # Non-circular BSGS
│   │       ├── ops/
│   │       │   ├── rns_fhe.rs          # RNS-based FHE operations
│   │       │   └── gso_fhe.rs          # GSO noise bounding layer
│   │       ├── entropy/
│   │       │   ├── crt_shadow.rs       # CRT Shadow entropy
│   │       │   ├── wassan_noise.rs     # Holographic noise field
│   │       │   └── secure.rs           # CSPRNG for keys
│   │       ├── keys/                   # Key generation
│   │       ├── noise/                  # Noise budget tracking
│   │       └── params/                 # FHE parameters
│   ├── mana/             # Modular arithmetic accelerator
│   └── unhal/            # Hardware abstraction layer
└── docs/
    ├── ENCRYPTED_QUANTUM_PAPER.md      # F4 paper
    ├── NON_CIRCULAR_ORDER_FINDING.md   # BSGS + K-elimination paper
    └── FHE_BENCHMARK_COMPARISON.md     # Industry comparison
```

---

## Workspace Crates

- **`nine65`**: Core FHE implementation (dual-RNS, K-Elimination, GSO-FHE, BFV ops)
- **`mana`**: Modular arithmetic accelerator
- **`unhal`**: Hardware abstraction and pipeline helpers

---

## Features

| Feature | Description |
|---------|-------------|
| `ntt_fft` (default) | FFT-based NTT implementation |
| `parallel` (default) | Rayon-based parallel paths |
| `accelerated` (default) | MANA + UNHAL integration |
| `wassan` | WASSAN holographic noise field (144 phi-harmonic) |
| `v2` | V2 integration tests |
| `secure-keygen` | Secure key generation (CSPRNG) |

---

## Build and Test

```bash
# Build release
cargo build --release --workspace

# Run all tests
cargo test --workspace --release

# Run with all features
cargo test -p nine65 --features v2,parallel,accelerated,wassan --release

# Run depth benchmark
cargo test --package nine65 --lib --release \
  ops::gso_fhe::depth_benchmarks::benchmark_max_depth -- --nocapture

# Run full arithmetic benchmark
cargo test --package nine65 --lib --release \
  ops::gso_fhe::arithmetic_benchmarks::benchmark_full_arithmetic -- --nocapture

# Run order finding tests
cargo test -p nine65 arithmetic::order_finding --release -- --nocapture
```

### Performance Tests (Opt-in)
```bash
NINE65_PERF_TESTS=1 cargo test -p nine65 --lib \
  entropy::wassan_noise::tests::test_benchmark_vs_shadow --release
```

---

## Quick Start

```rust
use nine65::params::secure_configs::SecureConfig;
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::ops::gso_fhe::GSOFHEContext;

// Create FHE context with production SecureConfig
let config = SecureConfig::secure_128().into_config();
let inner = RNSFHEContext::new_coeff_domain(&config);
let ctx = GSOFHEContext::new(inner);

// Generate keys
let keys = ctx.keygen();

// Encrypt
let ct_a = ctx.encrypt(42, &keys.public_key);
let ct_b = ctx.encrypt(7, &keys.public_key);

// Homomorphic operations (symmetric depth-50+ capable)
let ct_sum = ctx.add(&ct_a, &ct_b);
let ct_prod = ctx.mul(&ct_a, &ct_b, &keys.secret_key);

// Decrypt
let result = ctx.decrypt(&ct_prod, &keys.secret_key);
assert_eq!(result, 42 * 7);
```

### Public Mode (Multi-Party, Depth-Limited)

Public mode depth is limited; see docs/PUBLIC_MODE_DEPTH_BASELINE_2026-01-27.md for
current baselines.

```rust
use nine65::params::secure_configs::SecureConfig;
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::entropy::ShadowHarvester;

let config = SecureConfig::secure_192().into_config();
let ctx = RNSFHEContext::new_coeff_domain(&config);
let mut rng = ShadowHarvester::from_os_seed();

// Smaller decomposition base reduces relin noise for deeper public circuits
let keys = ctx.generate_keys_dual_full_public_deep(&mut rng);

let ct_a = ctx.encrypt_dual(2, &keys.public_key, &mut rng);
let ct_b = ctx.encrypt_dual(3, &keys.public_key, &mut rng);
let ct_prod = ctx.mul_dual_public(&ct_a, &ct_b, &keys.eval_key);
let result = ctx.decrypt_dual(&ct_prod, &keys.secret_key);

assert_eq!(result, 6);
```

---

## Security Notes

### Entropy Sources
| Operation | Entropy Source | Module |
|-----------|----------------|--------|
| Secret key generation | OS CSPRNG | `entropy::secure` |
| Public key randomness | OS CSPRNG | `entropy::secure` |
| Noise sampling | Shadow/Secure | `entropy::shadow` or `secure` |
| Testing/benchmarks | Deterministic | `entropy::shadow` |

### Documentation
- `docs/SECURITY_PROOFS.md` - Security assumptions and proofs
- `docs/FHE_BENCHMARK_COMPARISON.md` - Industry comparison with sources
- `docs/LATTICE_ESTIMATOR_BASELINE_2026-01-27.md` - LWE estimator baseline
- `docs/PUBLIC_MODE_DEPTH_BASELINE_2026-01-27.md` - public-mode depth sweep

---

## Technical Foundation

NINE65 is built on the QMNF (Quantized Modular Number Field) architecture:

1. **Integer-only arithmetic**: No floating-point in cryptographic runtime paths
2. **Stacked CRT**: Two-layer exact arithmetic (fast + unlimited precision)
3. **Fused Piggyback Division**: 40x faster RNS division via anchor-first computation
4. **Deterministic execution**: Bit-identical results across all platforms

---

## License

Proprietary. See `LICENSE`.

---

*Last updated: 2026-01-27*
*NINE65 - Bootstrap-Free FHE with K-Elimination*
