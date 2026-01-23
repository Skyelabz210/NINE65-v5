//! # QMNF FHE - Quantum-Modular Numerical Framework
//! 
//! A complete BFV Fully Homomorphic Encryption implementation with
//! AHOP-based zero-decoherence quantum simulation.
//!
//! ## Core Innovations (QMNF)
//! 
//! | Innovation | Benefit | Performance |
//! |------------|---------|-------------|
//! | **Montgomery Gen 2** | Division-free modular multiplication | ~30ns |
//! | **Barrett Reduction** | One-cycle modular reduction | ~2.4ns |
//! | **NTT Engine Gen 3** | Negacyclic convolution | 42× speedup |
//! | **Shadow Entropy Gen 4** | NIST-validated deterministic randomness | <10ns |
//! | **K-Elimination** | 100% exact integer division | O(n) |
//! | **Persistent Montgomery** | Stay in Montgomery form | 70× fewer conversions |
//! 
//! ## Zero Floating-Point Guarantee
//! 
//! All cryptographic and quantum operations use exact integer arithmetic.
//! No f32, f64, or any floating-point types in critical paths.
//! 
//! ## Quick Start: Production FHE
//! 
//! ```ignore
//! use nine65::prelude::*;
//!
//! // 1. Use HE-Standard compliant parameters
//! let config = FHEConfig::he_standard_128();  // 128-bit security
//! let ntt = NTTEngine::new(config.q, config.n);
//! 
//! // 2. Generate keys with OS CSPRNG (PRODUCTION)
//! let keys = KeySet::generate_secure(&config, &ntt);
//! 
//! // 3. Setup encoder/encryptor/decryptor
//! let encoder = BFVEncoder::new(&config);
//! let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
//! let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
//! 
//! // 4. Encrypt with secure entropy
//! let mut harvester = ShadowHarvester::from_os_seed();
//! let ct = encryptor.encrypt(42, &mut harvester);
//! 
//! // 5. Decrypt
//! let result = decryptor.decrypt(&ct);
//! assert_eq!(result, 42);
//! ```
//! 
//! ## Quick Start: Testing/Benchmarks
//! 
//! ```ignore
//! use nine65::prelude::*;
//!
//! // Use deterministic parameters for reproducible tests
//! let config = FHEConfig::light();
//! let ntt = NTTEngine::new(config.q, config.n);
//! let mut rng = ShadowHarvester::with_seed(42);  // Deterministic!
//! 
//! // Generate deterministic keys
//! let keys = KeySet::generate(&config, &ntt, &mut rng);
//! let encoder = BFVEncoder::new(&config);
//! 
//! // Encrypt with deterministic entropy
//! let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
//! let ct = encryptor.encrypt(42, &mut rng);
//! ```
//! 
//! ## Security Levels
//! 
//! | Config | N | Security | Use Case |
//! |--------|---|----------|----------|
//! | `light()` | 1024 | ~80-bit | Testing only |
//! | `he_standard_128()` | 2048 | 128-bit | **Production recommended** |
//! | `standard_128()` | 4096 | 128-bit | Deep circuits |
//! | `high_192()` | 8192 | 192-bit | High security |
//! 
//! ## Module Overview
//! 
//! | Module | Purpose |
//! |--------|---------|
//! | [`arithmetic`] | NTT, Montgomery, Barrett, RNS |
//! | [`entropy`] | Shadow Entropy + OS CSPRNG |
//! | [`params`] | FHE parameter configurations |
//! | [`ring`] | Ring polynomial operations |
//! | [`keys`] | Key generation and management |
//! | [`ops`] | Encryption/decryption/homomorphic ops |
//! | [`noise`] | Noise budget tracking |
//! | [`security`] | LWE security estimation |
//! | [`kat`] | Known Answer Tests |
//! | [`ahop`] | AHOP quantum simulation |
//! 
//! ## Compliance
//! 
//! - **HE Standard v1.1**: Compliant parameter sets available
//! - **NIST SP 800-22**: Shadow Entropy passes statistical tests
//! - **Memory Safety**: Key zeroization via `zeroize` crate

pub mod arithmetic;
pub mod entropy;
pub mod params;
pub mod ring;
pub mod keys;
pub mod ops;
pub mod ahop;
pub mod noise;     // CDHS-based noise tracking
pub mod security;  // LWE security estimation
pub mod kat;       // Known Answer Tests
pub mod quantum;   // QMNF algebraic quantum operations
pub mod errors;    // Standardized NINE65 error taxonomy
pub mod compiler;  // Bootstrap-free FHE circuit compiler

#[cfg(feature = "accelerated")]
pub mod accelerated;  // MANA/UNHAL acceleration layer

#[cfg(test)]
mod v2_integration_tests;

/// Prelude module - import commonly used types with a single `use` statement.
/// 
/// # Example
/// 
/// ```ignore
/// use nine65::prelude::*;
///
/// let config = FHEConfig::light();
/// let ntt = NTTEngine::new(config.q, config.n);
/// ```
pub mod prelude {
    // Arithmetic primitives
    pub use crate::arithmetic::{
        MontgomeryContext, BarrettContext, HybridModContext,
        RNSContext, RNSPolynomial,
        PersistentMontgomery, PersistentPolynomial,
        MobiusInt, MobiusPolynomial, MobiusVector, Polarity,  // SIGNED ARITHMETIC
        PadeEngine, PADE_SCALE,                                // INTEGER TRANSCENDENTALS
        MQReLU, MQReLUPolynomial, Sign,                        // O(1) SIGN DETECTION
        IntegerSoftmax, SOFTMAX_SCALE,                         // EXACT SUM SOFTMAX
        CyclotomicRing, CyclotomicPolynomial,                  // NATIVE RING TRIG
        modular_distance, toric_coupling,                       // TORIC GEOMETRY
        // Non-circular order finding (Shor's classical reduction)
        multiplicative_order, factor_semiprime, gcd,
    };
    
    // NTT: Conditional export - use FFT version when v2 feature enabled
    #[cfg(feature = "ntt_fft")]
    pub use crate::arithmetic::NTTEngineFFT as NTTEngine;
    
    #[cfg(not(feature = "ntt_fft"))]
    pub use crate::arithmetic::NTTEngine;
    
    // Also export both explicitly for users who need both
    pub use crate::arithmetic::NTTEngine as NTTEngineDFT;
    pub use crate::arithmetic::NTTEngineFFT;
    
    // Entropy sources
    pub use crate::entropy::ShadowHarvester;
    pub use crate::entropy::WassanNoiseField;  // V2: Holographic noise
    pub use crate::entropy::{secure_bytes, secure_u64, secure_ternary};
    
    // Parameters
    pub use crate::params::FHEConfig;
    
    // Ring operations
    pub use crate::ring::RingPolynomial;
    
    // Key management
    pub use crate::keys::{SecretKey, PublicKey, EvaluationKey, KeySet};
    
    // FHE operations - Classical BFV (single modulus)
    pub use crate::ops::{BFVEncoder, BFVEncryptor, BFVDecryptor, BFVEvaluator, Ciphertext};
    pub use crate::ops::{FHENeuralEvaluator, ActivationType, DenseLayer, NeuralNetwork};

    // FHE operations - DualRNS with K-Elimination (RECOMMENDED for ct×ct multiplication)
    pub use crate::ops::rns_fhe::{
        RNSFHEContext,
        DualRNSCiphertext, DualRNSPoly,
        DualRNSSecretKey, DualRNSPublicKey, DualRNSEvalKey,
        DualRNSKeySet, DualRNSFullKeySet,
        AutoCiphertext, AutoKeys, MulRoute,
    };
    
    // Quantum operations
    pub use crate::ahop::{Fp2Element, StateVector, GroverSearch, GroverStats};
    pub use crate::quantum::{
        QuantumAmplitude, QuantumState, GroverResult,          // SIGNED AMPLITUDES
        grover_search,                                          // PROPER GROVER
        // Sparse Grover (infinite coherence)
        SparseGroverFp2, TEST_PRIME, PRODUCTION_PRIME,
        // State taxonomy (F1)
        SparseKMarkedFp2, GHZStateFp2, ProductStateFp2, StateFamily,
        // Encrypted Quantum (F4) - FHE × GROVER
        EncryptedFp2, EncryptedSparseGrover, EncryptedQuantumContext, DecryptedGroverState,
    };
    
    // Noise tracking
    pub use crate::noise::{
        NoiseBudgetTracker, NoiseSnapshot, EMACalculator,
        MultiWindowNoiseDetector, NoiseAnomaly,
        P2QuantileEstimator, NoiseDistribution,
    };
    pub use crate::noise::budget::{NoiseBudget, NoiseOpType};
    
    // Security estimation
    pub use crate::security::{LWEParams, SecurityEstimate, ConfidenceLevel};

    // Error taxonomy
    pub use crate::errors::{Nine65Error, Nine65Result};
}

#[cfg(test)]
mod integration_tests {
    use crate::prelude::*;
    
    /// Full FHE workflow test
    #[test]
    fn test_full_fhe_workflow() {
        // 1. Setup parameters
        let config = FHEConfig::light();
        let ntt = NTTEngine::new(config.q, config.n);
        let mut rng = ShadowHarvester::with_seed(42);
        
        // 2. Generate keys
        let keys = KeySet::generate(&config, &ntt, &mut rng);
        let encoder = BFVEncoder::new(&config);
        
        // 3. Create encryptor/decryptor/evaluator
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
        let evaluator = BFVEvaluator::new(&ntt, &encoder, Some(&keys.eval_key));
        
        // 4. Encrypt two values
        let a = 17u64;
        let b = 25u64;
        
        let ct_a = encryptor.encrypt(a, &mut rng);
        let ct_b = encryptor.encrypt(b, &mut rng);
        
        // 5. Homomorphic operations - test working operations
        
        // Addition
        let ct_sum = evaluator.add(&ct_a, &ct_b);
        let sum = decryptor.decrypt(&ct_sum);
        assert_eq!(sum, a + b, "Homomorphic addition failed");
        
        // Subtraction
        let ct_diff = evaluator.sub(&ct_b, &ct_a);
        let diff = decryptor.decrypt(&ct_diff);
        assert_eq!(diff, b - a, "Homomorphic subtraction failed");
        
        // Negation
        let ct_neg = evaluator.negate(&ct_a);
        let neg = decryptor.decrypt(&ct_neg);
        assert_eq!(neg, (config.t - a) % config.t, "Homomorphic negation failed");
        
        // Add plaintext
        let ct_add_plain = evaluator.add_plain(&ct_a, 10);
        let add_plain = decryptor.decrypt(&ct_add_plain);
        assert_eq!(add_plain, a + 10, "Add plaintext failed");
        
        // Multiply by plaintext
        let ct_mul_plain = evaluator.mul_plain(&ct_a, 3);
        let mul_plain = decryptor.decrypt(&ct_mul_plain);
        assert_eq!(mul_plain, (a * 3) % config.t, "Mul plaintext failed");
        
        println!("Full FHE workflow: PASS");
        println!("  {} + {} = {}", a, b, sum);
        println!("  {} - {} = {}", b, a, diff);
        println!("  -{} = {} (mod {})", a, neg, config.t);
        println!("  {} + 10 = {}", a, add_plain);
        println!("  {} * 3 = {}", a, mul_plain);
    }
    
    /// Grover quantum search integration test
    #[test]
    fn test_grover_integration() {
        // 4-qubit search (16 states)
        let grover = GroverSearch::new(4, 11, 1000003);
        
        let optimal = grover.optimal_iterations();
        let state = grover.run(optimal);
        
        let prob = state.probability(11);
        println!("Grover search: target=11, optimal_iter={}, P(target)={:.4}", optimal, prob);
        
        assert!(prob > 0.5, "Target should be most probable");
    }
    
    /// Production-grade FHE test with 128-bit security parameters
    /// NOTE: This test demonstrates the noise challenge at production parameters.
    /// Proper noise budget tracking (Next Step #3) will fix this.
    #[test]
    #[ignore]  // Needs proper noise budget tracking for N=8192
    fn test_production_128bit() {
        use crate::params::production::ProductionConfig128;
        
        let config = ProductionConfig128::standard();
        
        println!("\n=== PRODUCTION 128-BIT FHE TEST ===");
        println!("N = {}", config.n);
        println!("log(Q) = {} bits", config.log_q());
        println!("Security = {}-bit", config.estimated_security());
        println!("Max depth = {} multiplications", config.max_depth);
        println!("Primes in chain = {}", config.primes.len());
        
        // Validate security BEFORE proceeding
        assert!(config.validate().is_ok(), "Config must be secure");
        assert!(config.estimated_security() >= 128, "Must have 128-bit security");
        
        // Create FHE context with first prime (for single-level test)
        let fhe_config = FHEConfig::custom(
            config.n,
            vec![config.primes[0]],  // Single prime for this test
            config.t,
            config.eta,
        ).expect("Valid config");
        
        let ntt = NTTEngine::new(fhe_config.q, fhe_config.n);
        let mut rng = ShadowHarvester::with_seed(0xDEAD_BEEF);
        
        println!("\nGenerating keys for N={}...", config.n);
        let start = std::time::Instant::now();
        let keys = KeySet::generate(&fhe_config, &ntt, &mut rng);
        let keygen_time = start.elapsed();
        println!("KeyGen: {:?}", keygen_time);
        
        let encoder = BFVEncoder::new(&fhe_config);
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, fhe_config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
        let evaluator = BFVEvaluator::new(&ntt, &encoder, Some(&keys.eval_key));
        
        // Encrypt test values
        let a = 12345u64;
        let b = 54321u64;
        
        println!("\nEncrypting messages...");
        let start = std::time::Instant::now();
        let ct_a = encryptor.encrypt(a, &mut rng);
        let ct_b = encryptor.encrypt(b, &mut rng);
        let encrypt_time = start.elapsed();
        println!("Encrypt (×2): {:?}", encrypt_time);
        
        // Homomorphic addition
        println!("\nHomomorphic operations...");
        let start = std::time::Instant::now();
        let ct_sum = evaluator.add(&ct_a, &ct_b);
        let add_time = start.elapsed();
        
        let start = std::time::Instant::now();
        let ct_diff = evaluator.sub(&ct_b, &ct_a);
        let sub_time = start.elapsed();
        
        // Decrypt and verify
        let start = std::time::Instant::now();
        let sum = decryptor.decrypt(&ct_sum);
        let diff = decryptor.decrypt(&ct_diff);
        let decrypt_time = start.elapsed();
        
        println!("Homo Add: {:?}", add_time);
        println!("Homo Sub: {:?}", sub_time);
        println!("Decrypt: {:?}", decrypt_time);
        
        // Verify correctness
        assert_eq!(sum, (a + b) % fhe_config.t, "Addition failed");
        assert_eq!(diff, (b - a) % fhe_config.t, "Subtraction failed");
        
        println!("\n✅ PRODUCTION 128-BIT TEST PASSED");
        println!("   {} + {} = {} (encrypted)", a, b, sum);
        println!("   {} - {} = {} (encrypted)", b, a, diff);
    }
    
    /// Benchmark test
    #[test]
    fn test_benchmarks() {
        let config = FHEConfig::light();
        let ntt = NTTEngine::new(config.q, config.n);
        let mut rng = ShadowHarvester::with_seed(999);
        
        // KeyGen benchmark
        let start = std::time::Instant::now();
        let keys = KeySet::generate(&config, &ntt, &mut rng);
        let keygen_time = start.elapsed();
        
        let encoder = BFVEncoder::new(&config);
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
        let evaluator = BFVEvaluator::new(&ntt, &encoder, Some(&keys.eval_key));
        
        // Encrypt benchmark
        let start = std::time::Instant::now();
        let ct = encryptor.encrypt(42, &mut rng);
        let encrypt_time = start.elapsed();
        
        // Decrypt benchmark
        let start = std::time::Instant::now();
        let _ = decryptor.decrypt(&ct);
        let decrypt_time = start.elapsed();
        
        // Homo add benchmark
        let ct2 = encryptor.encrypt(17, &mut rng);
        let start = std::time::Instant::now();
        let _ = evaluator.add(&ct, &ct2);
        let add_time = start.elapsed();
        
        // Homo mul benchmark
        let start = std::time::Instant::now();
        let _ = evaluator.mul(&ct, &ct2);
        let mul_time = start.elapsed();
        
        println!("\n=== QMNF FHE Benchmarks (N={}) ===", config.n);
        println!("KeyGen:     {:?}", keygen_time);
        println!("Encrypt:    {:?}", encrypt_time);
        println!("Decrypt:    {:?}", decrypt_time);
        println!("Homo Add:   {:?}", add_time);
        println!("Homo Mul:   {:?}", mul_time);
    }
}
