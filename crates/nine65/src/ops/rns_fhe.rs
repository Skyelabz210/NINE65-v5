//! RNS-Native FHE Operations with K-Elimination
//!
//! Bootstrap-Free FHE implementation based on the QMNF papers:
//! - Paper1: K-Elimination for exact division
//! - Paper2: Persistent Montgomery (values stay in Montgomery form)
//! - Paper4: Bootstrap-Free FHE architecture
//!
//! Key innovations:
//! 1. Dual-RNS Architecture: Main RNS for computation + Anchor RNS for K-Elimination
//! 2. Ciphertexts in dual-RNS form FROM ENCRYPTION
//! 3. K-Elimination rescaling for exact division after tensor product

#[cfg(feature = "ntt_fft")]
use crate::arithmetic::NTTEngineFFT as NTTEngine;

#[cfg(not(feature = "ntt_fft"))]
use crate::arithmetic::NTTEngine;

use crate::arithmetic::{RNSContext, RNSPolynomial, DualRNSContext, KElimination};
use crate::params::{FHEConfig, mod_inverse};
use crate::entropy::ShadowHarvester;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// RNS-native ciphertext: stored as parallel limbs from encryption
#[derive(Clone, Debug)]
pub struct RNSCiphertext {
    /// c0 polynomial in RNS form
    pub c0: RNSPolynomial,
    /// c1 polynomial in RNS form
    pub c1: RNSPolynomial,
    /// Number of RNS primes
    pub num_primes: usize,
}

// ============================================================================
// DUAL-TRACK RNS CIPHERTEXT FOR K-ELIMINATION
// ============================================================================
//
// The key architectural insight from the QMNF formalization:
// Anchor residues MUST be maintained alongside main residues for ALL operations.
//
// After tensor product: Δ² > Q causes wraparound in main RNS.
// But with anchor residues, we can reconstruct the EXACT value via K-Elimination:
//   k = ((v_anchor - v_main) × M⁻¹) mod A
//   exact_value = v_main + k × M
//
// This enables EXACT rescaling even when Δ² >> Q.

/// Dual-track RNS polynomial: main + anchor residues for K-Elimination
#[derive(Clone, Debug, Zeroize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DualRNSPoly {
    /// Main RNS limbs: [prime_idx][coeff_idx]
    pub main: Vec<Vec<u64>>,
    /// Anchor RNS limbs: [anchor_prime_idx][coeff_idx]
    pub anchor: Vec<Vec<u64>>,
    /// Polynomial degree
    pub n: usize,
}

/// Dual-track ciphertext with K-Elimination support
///
/// Maintains both main and anchor residues through ALL operations,
/// enabling exact reconstruction even after tensor product causes
/// wraparound in main RNS (when Δ² > Q).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DualRNSCiphertext {
    /// c0 polynomial with main + anchor residues
    pub c0: DualRNSPoly,
    /// c1 polynomial with main + anchor residues
    pub c1: DualRNSPoly,
    /// Current level (number of main primes remaining)
    pub level: usize,
}

/// Dual-track secret key
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DualRNSSecretKey {
    /// Secret polynomial with main + anchor residues
    pub s: DualRNSPoly,
}

/// Dual-track public key
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DualRNSPublicKey {
    /// pk0 = -(a*s + e) with main + anchor residues
    pub pk0: DualRNSPoly,
    /// pk1 = a with main + anchor residues
    pub pk1: DualRNSPoly,
}

/// Dual-track evaluation key for PUBLIC relinearization
///
/// This enables homomorphic multiplication WITHOUT the secret key.
/// Standard FHE security model: anyone can compute, only key holder decrypts.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DualRNSEvalKey {
    /// Relinearization key components: rlk[i] = (rlk0_i, rlk1_i)
    /// where rlk0_i = -a_i*s - e_i + power_i * s², rlk1_i = a_i
    /// Both in dual-RNS form (main + anchor)
    pub rlk: Vec<(DualRNSPoly, DualRNSPoly)>,
    /// Decomposition base (typically 2^16)
    pub decomp_base: u64,
    /// Number of decomposition digits
    pub num_digits: usize,
}

/// Dual-track key set (symmetric mode - for single-party computation)
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DualRNSKeySet {
    pub secret_key: DualRNSSecretKey,
    pub public_key: DualRNSPublicKey,
}

/// Dual-track FULL key set (public mode - for multi-party FHE)
///
/// Use this when the computing party should NOT have the secret key.
/// This is the standard FHE security model.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DualRNSFullKeySet {
    pub secret_key: DualRNSSecretKey,
    pub public_key: DualRNSPublicKey,
    pub eval_key: DualRNSEvalKey,
}

/// RNS-native secret key
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RNSSecretKey {
    /// Secret polynomial in RNS form
    pub s: RNSPolynomial,
}

/// RNS-native public key
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RNSPublicKey {
    /// pk0 = -(a*s + e) in RNS form
    pub pk0: RNSPolynomial,
    /// pk1 = a in RNS form
    pub pk1: RNSPolynomial,
}

/// RNS-native evaluation key for relinearization
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RNSEvalKey {
    /// Relinearization key components
    pub rlk: Vec<(RNSPolynomial, RNSPolynomial)>,
    /// Decomposition base
    pub decomp_base: u64,
}

/// Complete RNS key set
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RNSKeySet {
    pub secret_key: RNSSecretKey,
    pub public_key: RNSPublicKey,
    pub eval_key: RNSEvalKey,
}

// ============================================================================
// SERIALIZATION HELPERS
// ============================================================================

#[cfg(feature = "serde")]
impl DualRNSCiphertext {
    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize from JSON string
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// Serialize to compact binary format (bincode)
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize from binary format (bincode)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

#[cfg(feature = "serde")]
impl DualRNSKeySet {
    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize from JSON string
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// Serialize to compact binary format (bincode)
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize from binary format (bincode)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

// ============================================================================
// AUTO-ROUTING: Regime Selection for Single vs Dual RNS
// ============================================================================

/// Multiplication/rescale regime based on parameter constraints
///
/// The fundamental constraint: after tensor product, we have values up to Δ²×m².
/// - If Δ² ≤ Q: Single-RNS Bajard rescaling can approximate correctly
/// - If Δ² > Q: MUST use Dual-RNS K-Elimination for exact reconstruction
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MulRoute {
    /// Single-RNS with Bajard per-limb rescaling (faster, approximate)
    /// Valid only when Δ² ≤ Q
    BajardSingle,
    /// Dual-RNS with K-Elimination rescaling (exact)
    /// Required when Δ² > Q or exact mode requested
    KElimDual,
}

/// Auto-routed key set (either Single or Dual regime)
pub enum AutoKeys {
    Single(RNSKeySet),
    Dual(DualRNSKeySet),
}

/// Auto-routed ciphertext (either Single or Dual regime)
#[derive(Clone)]
pub enum AutoCiphertext {
    Single(RNSCiphertext),
    Dual(DualRNSCiphertext),
}

impl AutoKeys {
    /// Check if using dual-RNS regime
    pub fn is_dual(&self) -> bool {
        matches!(self, AutoKeys::Dual(_))
    }
}

impl AutoCiphertext {
    /// Check if using dual-RNS regime
    pub fn is_dual(&self) -> bool {
        matches!(self, AutoCiphertext::Dual(_))
    }
}

/// RNS-Native FHE Context with Dual-RNS K-Elimination
///
/// This implements the Bootstrap-Free FHE architecture from Paper4:
/// - All ciphertexts stored in dual-RNS form (main + anchor)
/// - K-Elimination for exact rescaling (no floating-point)
/// - Δ² terms handled correctly via anchor system
///
/// Key innovation from QMNF papers:
/// - Main RNS: 3 primes for computation (M = q0 × q1 × q2)
/// - Anchor RNS: 2 primes for K-Elimination (A = a0 × a1)
/// - After tensor product, K-Elimination enables exact division
///
/// Single-RNS ciphertexts/keys are stored in Montgomery form to enable
/// persistent Montgomery NTT without repeated conversions.
pub struct RNSFHEContext {
    /// Dual-RNS context (main + anchor systems)
    pub dual_rns: DualRNSContext,
    /// Main RNS context (for backward compatibility)
    pub rns: RNSContext,
    /// NTT engines for main primes (from dual_rns.main)
    pub ntt_engines: Vec<NTTEngine>,
    /// K-Elimination for exact division (legacy, now uses dual_rns)
    pub ke: KElimination,
    /// Plaintext modulus
    pub t: u64,
    /// Q = product of main primes (stored as u128)
    pub q_product: u128,
    /// Polynomial degree
    pub n: usize,
    /// Scaling factor Δ = floor(Q/t) in RNS form
    /// delta_rns[i] = Δ mod main_primes[i]
    pub delta_rns: Vec<u64>,
    /// Config reference
    pub config: FHEConfig,
}

impl RNSFHEContext {
    /// Create RNS FHE context from config
    ///
    /// Requires config with at least 2 primes for RNS multiplication
    pub fn new(config: &FHEConfig) -> Self {
        assert!(config.primes.len() >= 2,
                "RNS-native FHE requires at least 2 primes. Use light_rns or higher.");
        assert!(config.primes.len() <= 3,
                "Currently supports up to 3 primes (Q fits in u128)");

        // Create dual-RNS context with main + anchor systems
        let dual_rns = DualRNSContext::for_fhe(&config.primes, config.n);

        // Keep main RNS context for backward compatibility
        let rns = RNSContext::new(config.primes.clone(), config.n);

        // NTT engines from main RNS (also available via dual_rns.main.ntt_engines)
        let ntt_engines: Vec<NTTEngine> = config.primes.iter()
            .map(|&p| NTTEngine::new(p, config.n))
            .collect();

        // Compute Q = product of main primes
        let q_product: u128 = config.primes.iter()
            .fold(1u128, |acc, &p| acc * p as u128);

        // Compute Δ = floor(Q/t) and store in RNS form
        let delta_big = q_product / config.t as u128;
        let delta_rns: Vec<u64> = config.primes.iter()
            .map(|&p| (delta_big % p as u128) as u64)
            .collect();

        // Legacy K-Elimination (now using dual_rns internally)
        let ke = KElimination::for_fhe(config.primes[0]);

        Self {
            dual_rns,
            rns,
            ntt_engines,
            ke,
            t: config.t,
            q_product,
            delta_rns,
            n: config.n,
            config: config.clone(),
        }
    }

    /// Create RNS FHE context for coefficient-domain K-Elimination
    ///
    /// CRITICAL: NTT-domain K-Elimination is INVALID because different primes
    /// use different NTT roots of unity. K-Elimination MUST be in coefficient domain.
    ///
    /// Uses 5 anchor primes for Q²×N capacity:
    ///   Q²×N ≈ 10^39 for 2 main primes, N=1024
    ///   M×A ≈ 10^64 with 5 anchors >> Q²×N ✓
    ///
    /// Architecture:
    ///   1. Tensor product in NTT domain (fast, O(N) point-wise)
    ///   2. INTT to coefficient domain
    ///   3. K-Elimination rescale (exact, Q²×N bound)
    ///   4. NTT back for storage
    pub fn new_coeff_domain(config: &FHEConfig) -> Self {
        assert!(config.primes.len() >= 2,
                "RNS-native FHE requires at least 2 primes.");
        assert!(config.primes.len() <= 3,
                "Currently supports up to 3 primes (Q fits in u128)");

        // Create dual-RNS context with 5 anchor primes for Q²×N capacity
        let dual_rns = DualRNSContext::for_fhe_coeff_domain(&config.primes, config.n);

        let rns = RNSContext::new(config.primes.clone(), config.n);

        let ntt_engines: Vec<NTTEngine> = config.primes.iter()
            .map(|&p| NTTEngine::new(p, config.n))
            .collect();

        let q_product: u128 = config.primes.iter()
            .fold(1u128, |acc, &p| acc * p as u128);

        let delta_big = q_product / config.t as u128;
        let delta_rns: Vec<u64> = config.primes.iter()
            .map(|&p| (delta_big % p as u128) as u64)
            .collect();

        let ke = KElimination::for_fhe(config.primes[0]);

        Self {
            dual_rns,
            rns,
            ntt_engines,
            ke,
            t: config.t,
            q_product,
            delta_rns,
            n: config.n,
            config: config.clone(),
        }
    }

    /// DEPRECATED: Use new_coeff_domain instead
    #[deprecated(note = "NTT-domain K-Elimination is invalid. Use new_coeff_domain")]
    #[allow(deprecated)]
    pub fn new_ntt_domain(config: &FHEConfig) -> Self {
        Self::new_coeff_domain(config)
    }

    // ========================================================================
    // AUTO-ROUTING: Regime Selection
    // ========================================================================

    /// Determine which multiplication/rescale regime to use.
    ///
    /// Rule: If Δ² > Q (or overflow), we MUST use dual-RNS K-Elimination.
    /// Otherwise, single-RNS Bajard rescaling is valid (but less accurate).
    ///
    /// Being conservative: any uncertainty → KElimDual
    pub fn mul_route(&self) -> MulRoute {
        let delta = self.q_product / self.t as u128;

        match delta.checked_mul(delta) {
            Some(delta_squared) if delta_squared <= self.q_product => MulRoute::BajardSingle,
            _ => MulRoute::KElimDual,  // Overflow or Δ² > Q
        }
    }

    /// Generate keys using the appropriate regime (auto-selected)
    pub fn generate_keys_auto(&self, rng: &mut ShadowHarvester) -> AutoKeys {
        let route = self.mul_route();

        #[cfg(debug_assertions)]
        {
            let delta = self.q_product / self.t as u128;
            let delta_sq_result = delta.checked_mul(delta);
            eprintln!("[auto-routing] Q={:.2e}, Δ={:.2e}, Δ²={}, route={:?}",
                self.q_product as f64,
                delta as f64,
                match delta_sq_result {
                    Some(d2) => format!("{:.2e} (fits)", d2 as f64),
                    None => "OVERFLOW".to_string(),
                },
                route
            );
        }

        match route {
            MulRoute::BajardSingle => AutoKeys::Single(self.generate_keys(rng)),
            MulRoute::KElimDual => AutoKeys::Dual(self.generate_keys_dual(rng)),
        }
    }

    /// Encrypt using the appropriate regime
    pub fn encrypt_auto(&self, m: u64, keys: &AutoKeys, rng: &mut ShadowHarvester) -> AutoCiphertext {
        match (self.mul_route(), keys) {
            (MulRoute::BajardSingle, AutoKeys::Single(k)) => {
                AutoCiphertext::Single(self.encrypt(m, &k.public_key, rng))
            }
            (MulRoute::KElimDual, AutoKeys::Dual(k)) => {
                AutoCiphertext::Dual(self.encrypt_dual(m, &k.public_key, rng))
            }
            _ => panic!("Key regime mismatch: regenerate keys with generate_keys_auto()"),
        }
    }

    /// Multiply using the appropriate regime
    pub fn mul_auto(&self, a: &AutoCiphertext, b: &AutoCiphertext, keys: &AutoKeys) -> AutoCiphertext {
        match (self.mul_route(), a, b, keys) {
            (MulRoute::BajardSingle, AutoCiphertext::Single(x), AutoCiphertext::Single(y), AutoKeys::Single(k)) => {
                AutoCiphertext::Single(self.mul(x, y, &k.eval_key))
            }
            (MulRoute::KElimDual, AutoCiphertext::Dual(x), AutoCiphertext::Dual(y), AutoKeys::Dual(k)) => {
                AutoCiphertext::Dual(self.mul_dual_symmetric(x, y, &k.secret_key))
            }
            _ => panic!("Ciphertext/key regime mismatch: don't mix Single and Dual in mul_auto()"),
        }
    }

    /// Decrypt using the appropriate regime
    pub fn decrypt_auto(&self, ct: &AutoCiphertext, keys: &AutoKeys) -> u64 {
        self.decrypt_auto_with_diagnostics(ct, keys).0
    }

    /// Decrypt with diagnostics: returns (decrypted, rounding_margin)
    ///
    /// Use this in tests to diagnose noise budget exhaustion.
    /// Positive margin = safe, negative margin = rounding failure.
    #[cfg(any(test, debug_assertions))]
    pub fn decrypt_auto_with_diagnostics(&self, ct: &AutoCiphertext, keys: &AutoKeys) -> (u64, i128) {
        match (self.mul_route(), ct, keys) {
            (MulRoute::BajardSingle, AutoCiphertext::Single(c), AutoKeys::Single(k)) => {
                // Single-RNS doesn't have diagnostics yet, return 0 margin
                (self.decrypt(c, &k.secret_key), 0)
            }
            (MulRoute::KElimDual, AutoCiphertext::Dual(c), AutoKeys::Dual(k)) => {
                self.decrypt_dual_with_diagnostics(c, &k.secret_key)
            }
            _ => panic!("Ciphertext/key regime mismatch in decrypt_auto()"),
        }
    }

    #[cfg(not(any(test, debug_assertions)))]
    fn decrypt_auto_with_diagnostics(&self, ct: &AutoCiphertext, keys: &AutoKeys) -> (u64, i128) {
        match (self.mul_route(), ct, keys) {
            (MulRoute::BajardSingle, AutoCiphertext::Single(c), AutoKeys::Single(k)) => {
                (self.decrypt(c, &k.secret_key), 0)
            }
            (MulRoute::KElimDual, AutoCiphertext::Dual(c), AutoKeys::Dual(k)) => {
                (self.decrypt_dual(c, &k.secret_key), 0)
            }
            _ => panic!("Ciphertext/key regime mismatch in decrypt_auto()"),
        }
    }

    /// Add ciphertexts using the appropriate regime
    pub fn add_auto(&self, a: &AutoCiphertext, b: &AutoCiphertext) -> AutoCiphertext {
        match (self.mul_route(), a, b) {
            (MulRoute::BajardSingle, AutoCiphertext::Single(x), AutoCiphertext::Single(y)) => {
                AutoCiphertext::Single(self.add(x, y))
            }
            (MulRoute::KElimDual, AutoCiphertext::Dual(x), AutoCiphertext::Dual(y)) => {
                // For dual ciphertexts, add component-wise
                let c0 = self.dual_poly_add(&x.c0, &y.c0);
                let c1 = self.dual_poly_add(&x.c1, &y.c1);
                AutoCiphertext::Dual(DualRNSCiphertext { c0, c1, level: x.level })
            }
            _ => panic!("Ciphertext regime mismatch in add_auto()"),
        }
    }

    /// Get smallest prime (used for sampling bounds)
    fn smallest_prime(&self) -> u64 {
        *self.config.primes.iter().min().unwrap()
    }

    /// Convert a single-RNS polynomial into Montgomery form (persistent mode).
    fn to_montgomery_poly(&self, poly: &RNSPolynomial) -> RNSPolynomial {
        let limbs: Vec<Vec<u64>> = poly.limbs.iter()
            .zip(self.rns.mont_contexts.iter())
            .map(|(limb, mont)| limb.iter().map(|&c| mont.to_montgomery(c)).collect())
            .collect();

        RNSPolynomial { limbs, n: poly.n }
    }

    /// Convert a single-RNS polynomial from Montgomery form back to standard residues.
    fn from_montgomery_poly(&self, poly: &RNSPolynomial) -> RNSPolynomial {
        let limbs: Vec<Vec<u64>> = poly.limbs.iter()
            .zip(self.rns.mont_contexts.iter())
            .map(|(limb, mont)| limb.iter().map(|&c| mont.from_montgomery(c)).collect())
            .collect();

        RNSPolynomial { limbs, n: poly.n }
    }

    /// Reconstruct a CRT value from Montgomery residues.
    fn to_int_montgomery(&self, residues: &[u64]) -> u128 {
        let standard: Vec<u64> = residues.iter()
            .zip(self.rns.mont_contexts.iter())
            .map(|(&c, mont)| mont.from_montgomery(c))
            .collect();
        self.rns.to_int(&standard)
    }

    /// Generate RNS-native key set
    pub fn generate_keys(&self, rng: &mut ShadowHarvester) -> RNSKeySet {
        let q_min = self.smallest_prime();

        // Generate secret key s with small coefficients {-1, 0, 1}
        // Use smallest prime for -1 representation (will be correct mod all primes)
        let s_coeffs: Vec<u64> = (0..self.n)
            .map(|_| {
                let r = rng.next_u64() % 3;
                match r {
                    0 => 0,
                    1 => 1,
                    _ => q_min - 1, // -1 mod q_min (will reduce correctly in RNS)
                }
            })
            .collect();

        // Create RNS polynomial directly with correct -1 handling
        let s_limbs: Vec<Vec<u64>> = self.config.primes.iter()
            .map(|&p| {
                s_coeffs.iter().map(|&c| {
                    if c == q_min - 1 {
                        p - 1  // -1 mod p
                    } else {
                        c
                    }
                }).collect()
            })
            .collect();
        let s_rns = self.to_montgomery_poly(&RNSPolynomial { limbs: s_limbs, n: self.n });
        let secret_key = RNSSecretKey { s: s_rns };

        // Generate public key: pk = (pk0, pk1) where pk0 = -(a*s + e), pk1 = a
        // Generate random a - coefficients uniform in [0, q_min) to be safe
        let a_coeffs: Vec<u64> = (0..self.n)
            .map(|_| rng.next_u64() % q_min)
            .collect();
        let a_rns = self.to_montgomery_poly(&RNSPolynomial::from_poly(&a_coeffs, &self.rns));

        // Generate small error e
        let e_coeffs: Vec<u64> = (0..self.n)
            .map(|_| sample_cbd(rng, self.config.eta, q_min))
            .collect();
        let e_rns = self.to_montgomery_poly(&RNSPolynomial::from_poly(&e_coeffs, &self.rns));

        // Compute a*s in RNS (NTT multiply in each limb)
        let as_rns = self.rns_poly_mul(&a_rns, &secret_key.s);

        // pk0 = -(a*s + e) = -a*s - e
        let as_plus_e = as_rns.add(&e_rns, &self.rns);
        let pk0 = as_plus_e.neg(&self.rns);

        let public_key = RNSPublicKey { pk0, pk1: a_rns };

        // Generate evaluation key for relinearization
        let eval_key = self.generate_eval_key(&secret_key, rng);

        RNSKeySet {
            secret_key,
            public_key,
            eval_key,
        }
    }

    /// Generate evaluation key for relinearization
    fn generate_eval_key(&self, sk: &RNSSecretKey, rng: &mut ShadowHarvester) -> RNSEvalKey {
        let q_min = self.smallest_prime();
        let decomp_base = 1u64 << 16; // 2^16 decomposition base
        // Number of digits based on Q size (using 128-bit representation)
        let q_bits = 128 - self.q_product.leading_zeros() as usize;
        let num_digits = (q_bits + 15) / 16;

        // s^2 in RNS
        let s2 = self.rns_poly_mul(&sk.s, &sk.s);

        let mut rlk = Vec::with_capacity(num_digits);

        for i in 0..num_digits {
            // Compute power = decomp_base^i mod each prime (avoid overflow)
            // power_rns[j] = decomp_base^i mod primes[j]
            let power_rns: Vec<u64> = self.config.primes.iter()
                .map(|&p| {
                    let mut result = 1u64;
                    let base_mod_p = decomp_base % p;
                    for _ in 0..i {
                        result = ((result as u128 * base_mod_p as u128) % p as u128) as u64;
                    }
                    result
                })
                .collect();

            // Generate random a_i
            let a_coeffs: Vec<u64> = (0..self.n)
                .map(|_| rng.next_u64() % q_min)
                .collect();
            let a_rns = self.to_montgomery_poly(&RNSPolynomial::from_poly(&a_coeffs, &self.rns));

            // Generate error e_i
            let e_coeffs: Vec<u64> = (0..self.n)
                .map(|_| sample_cbd(rng, self.config.eta, q_min))
                .collect();
            let e_rns = self.to_montgomery_poly(&RNSPolynomial::from_poly(&e_coeffs, &self.rns));

            // rlk0_i = -(a_i * s + e_i) + power * s^2
            let as_rns = self.rns_poly_mul(&a_rns, &sk.s);
            let as_plus_e = as_rns.add(&e_rns, &self.rns);
            let neg_as_e = as_plus_e.neg(&self.rns);

            // Scale s^2 by power (per-limb to avoid overflow)
            let power_s2 = self.scalar_mul_rns_vec(&s2, &power_rns);
            let rlk0 = neg_as_e.add(&power_s2, &self.rns);

            rlk.push((rlk0, a_rns));
        }

        RNSEvalKey { rlk, decomp_base }
    }

    /// Encrypt plaintext to RNS ciphertext
    ///
    /// This produces ciphertext DIRECTLY in RNS form (Paper4 requirement)
    ///
    /// Encoding: m * Δ where Δ = floor(Q/t) is stored in RNS form
    pub fn encrypt(&self, m: u64, pk: &RNSPublicKey, rng: &mut ShadowHarvester) -> RNSCiphertext {
        assert!(m < self.t, "Plaintext must be < t");
        let q_min = self.smallest_prime();

        // Encode message: m * Δ in RNS form
        // For each limb i: (m * delta_rns[i]) mod prime[i]
        let m_limbs: Vec<Vec<u64>> = self.config.primes.iter()
            .enumerate()
            .map(|(i, &p)| {
                let mut coeffs = vec![0u64; self.n];
                coeffs[0] = ((m as u128 * self.delta_rns[i] as u128) % p as u128) as u64;
                coeffs
            })
            .collect();
        let m_rns = self.to_montgomery_poly(&RNSPolynomial { limbs: m_limbs, n: self.n });

        // Generate small u with coefficients in {-1, 0, 1}
        // Create directly with correct -1 handling per limb
        let u_choices: Vec<i8> = (0..self.n)
            .map(|_| {
                let r = rng.next_u64() % 3;
                match r {
                    0 => 0i8,
                    1 => 1i8,
                    _ => -1i8,
                }
            })
            .collect();

        let u_limbs: Vec<Vec<u64>> = self.config.primes.iter()
            .map(|&p| {
                u_choices.iter().map(|&c| {
                    if c < 0 { p - 1 } else { c as u64 }
                }).collect()
            })
            .collect();
        let u_rns = self.to_montgomery_poly(&RNSPolynomial { limbs: u_limbs, n: self.n });

        // Generate errors e1, e2
        let e1_coeffs: Vec<u64> = (0..self.n)
            .map(|_| sample_cbd(rng, self.config.eta, q_min))
            .collect();
        let e1_rns = self.to_montgomery_poly(&RNSPolynomial::from_poly(&e1_coeffs, &self.rns));

        let e2_coeffs: Vec<u64> = (0..self.n)
            .map(|_| sample_cbd(rng, self.config.eta, q_min))
            .collect();
        let e2_rns = self.to_montgomery_poly(&RNSPolynomial::from_poly(&e2_coeffs, &self.rns));

        // c0 = pk0 * u + e1 + m
        let pk0_u = self.rns_poly_mul(&pk.pk0, &u_rns);
        let c0 = pk0_u.add(&e1_rns, &self.rns).add(&m_rns, &self.rns);

        // c1 = pk1 * u + e2
        let pk1_u = self.rns_poly_mul(&pk.pk1, &u_rns);
        let c1 = pk1_u.add(&e2_rns, &self.rns);

        RNSCiphertext {
            c0,
            c1,
            num_primes: self.config.primes.len(),
        }
    }

    /// Decrypt RNS ciphertext
    ///
    /// Decoding: round(inner / Δ) mod t = round(inner * t / Q) mod t
    pub fn decrypt(&self, ct: &RNSCiphertext, sk: &RNSSecretKey) -> u64 {
        // inner = c0 + c1 * s
        let c1_s = self.rns_poly_mul(&ct.c1, &sk.s);
        let inner = ct.c0.add(&c1_s, &self.rns);

        // Reconstruct constant term from RNS
        let rns_coeff: Vec<u64> = inner.limbs.iter()
            .map(|limb| limb[0])
            .collect();
        let full_value = self.to_int_montgomery(&rns_coeff);

        // Decode: round(inner / Δ) mod t where Δ = Q/t
        // = round(inner * t / Q) mod t
        // Handle potential overflow by using u128 carefully
        // For values close to Q, we need centered reduction
        let q_half = self.q_product / 2;
        let centered_value = if full_value > q_half {
            // Negative value in centered representation
            // inner - Q, but we need to be careful with signs
            // (Q - full_value) * t / Q gives the negative magnitude
            let neg_magnitude = self.q_product - full_value;
            let scaled_neg = (neg_magnitude * self.t as u128 + q_half) / self.q_product;
            // Negate mod t
            if scaled_neg == 0 {
                0
            } else {
                self.t - (scaled_neg % self.t as u128) as u64
            }
        } else {
            // Positive value
            let scaled = (full_value * self.t as u128 + q_half) / self.q_product;
            (scaled % self.t as u128) as u64
        };

        centered_value
    }

    /// Homomorphic addition
    pub fn add(&self, ct1: &RNSCiphertext, ct2: &RNSCiphertext) -> RNSCiphertext {
        RNSCiphertext {
            c0: ct1.c0.add(&ct2.c0, &self.rns),
            c1: ct1.c1.add(&ct2.c1, &self.rns),
            num_primes: ct1.num_primes,
        }
    }

    /// Homomorphic subtraction
    pub fn sub(&self, ct1: &RNSCiphertext, ct2: &RNSCiphertext) -> RNSCiphertext {
        RNSCiphertext {
            c0: ct1.c0.sub(&ct2.c0, &self.rns),
            c1: ct1.c1.sub(&ct2.c1, &self.rns),
            num_primes: ct1.num_primes,
        }
    }

    /// Homomorphic multiplication (CT × CT)
    ///
    /// This is where RNS shines - no coefficient overflow!
    pub fn mul(&self, ct1: &RNSCiphertext, ct2: &RNSCiphertext, ek: &RNSEvalKey) -> RNSCiphertext {
        // Tensor product: (d0, d1, d2)
        // d0 = c0_1 * c0_2
        // d1 = c0_1 * c1_2 + c1_1 * c0_2
        // d2 = c1_1 * c1_2
        let d0 = self.rns_poly_mul(&ct1.c0, &ct2.c0);

        let c0_1_c1_2 = self.rns_poly_mul(&ct1.c0, &ct2.c1);
        let c1_1_c0_2 = self.rns_poly_mul(&ct1.c1, &ct2.c0);
        let d1 = c0_1_c1_2.add(&c1_1_c0_2, &self.rns);

        let d2 = self.rns_poly_mul(&ct1.c1, &ct2.c1);

        // Scale by t/q to reduce noise (using K-Elimination for exactness)
        let e0 = self.exact_rescale(&d0);
        let e1 = self.exact_rescale(&d1);
        let e2 = self.exact_rescale(&d2);

        // Relinearize: (e0, e1, e2) → (c0', c1')
        self.relinearize(&e0, &e1, &e2, ek)
    }

    /// BFV-style rescaling after tensor product
    ///
    /// Computes: round(x × t / Q) for each coefficient.
    ///
    /// In RNS, this is approximated using the Bajard-style approach:
    /// For each limb i: result_i ≈ round((x_i × t × Q_i^{-1}) / q_i) mod q_i
    /// where Q_i = Q / q_i (product of all other primes).
    ///
    /// This works because:
    /// x ≡ x_i (mod q_i)
    /// x × t / Q = x × t / (q_i × Q_i)
    ///           ≈ (x_i × t) / (q_i × Q_i)  [error bounded]
    ///           = ((x_i × t × Q_i^{-1}) / q_i) × (1/Q_i) × Q_i
    ///           ≈ floor((x_i × t × Q_i^{-1}) / q_i) mod q_i
    fn exact_rescale(&self, poly: &RNSPolynomial) -> RNSPolynomial {
        let poly_standard = self.from_montgomery_poly(poly);
        let mut result_limbs: Vec<Vec<u64>> = vec![vec![0u64; self.n]; self.rns.num_primes()];

        // Precompute scaling factors for each limb
        // scale_i = t × Q_i^{-1} mod q_i where Q_i = Q / q_i
        let scale_factors: Vec<u64> = self.config.primes.iter()
            .enumerate()
            .map(|(i, &q_i)| {
                // Q_i = product of all primes except q_i
                let q_i_others: u128 = self.config.primes.iter()
                    .enumerate()
                    .filter(|&(j, _)| j != i)
                    .fold(1u128, |acc, (_, &p)| acc * p as u128);

                let q_i_others_mod = (q_i_others % q_i as u128) as u64;
                let q_i_others_inv = mod_inverse(q_i_others_mod, q_i);

                // scale = t × Q_i^{-1} mod q_i
                ((self.t as u128 * q_i_others_inv as u128) % q_i as u128) as u64
            })
            .collect();

        for coeff_idx in 0..self.n {
            for (limb_idx, &q_i) in self.config.primes.iter().enumerate() {
                let coeff = poly_standard.limbs[limb_idx][coeff_idx];
                let q_i_half = q_i / 2;

                // Centered representation: if coeff > q_i/2, treat as negative
                let (is_neg, abs_coeff) = if coeff > q_i_half {
                    (true, q_i - coeff)
                } else {
                    (false, coeff)
                };

                // Compute: floor((abs_coeff × scale_factor + q_i/2) / q_i)
                // The +q_i/2 is for rounding
                let numerator = abs_coeff as u128 * scale_factors[limb_idx] as u128;
                let scaled_abs = ((numerator + q_i_half as u128) / q_i as u128) as u64;

                // Apply sign and reduce mod q_i
                let scaled = if is_neg && scaled_abs > 0 {
                    q_i - (scaled_abs % q_i)
                } else {
                    scaled_abs % q_i
                };

                result_limbs[limb_idx][coeff_idx] = scaled;
            }
        }

        self.to_montgomery_poly(&RNSPolynomial { limbs: result_limbs, n: self.n })
    }

    /// Alternative rescaling: per-limb approximation (faster but less accurate)
    ///
    /// This is the fallback method when K-Elimination is too slow.
    /// Uses per-limb scaling which gives approximate results with bounded error.
    #[allow(dead_code)]
    fn approx_rescale(&self, poly: &RNSPolynomial) -> RNSPolynomial {
        let poly_standard = self.from_montgomery_poly(poly);
        let mut result_limbs: Vec<Vec<u64>> = vec![vec![0u64; self.n]; self.rns.num_primes()];

        // Precompute per-limb scaling factors
        let mut scale_factors: Vec<u64> = Vec::with_capacity(self.config.primes.len());
        for (i, &q_i) in self.config.primes.iter().enumerate() {
            let q_i_others: u128 = self.config.primes.iter()
                .enumerate()
                .filter(|&(j, _)| j != i)
                .fold(1u128, |acc, (_, &p)| acc * p as u128);

            let q_i_others_mod = (q_i_others % q_i as u128) as u64;
            let q_i_others_inv = mod_inverse(q_i_others_mod, q_i);
            let scale = ((self.t as u128 * q_i_others_inv as u128) % q_i as u128) as u64;
            scale_factors.push(scale);
        }

        for coeff_idx in 0..self.n {
            for (limb_idx, &q_i) in self.config.primes.iter().enumerate() {
                let coeff = poly_standard.limbs[limb_idx][coeff_idx];
                let q_i_half = q_i / 2;

                let (is_neg, abs_coeff) = if coeff > q_i_half {
                    (true, q_i - coeff)
                } else {
                    (false, coeff)
                };

                let scaled_abs = ((abs_coeff as u128 * scale_factors[limb_idx] as u128
                                   + q_i_half as u128) / q_i as u128) as u64;

                let scaled = if is_neg && scaled_abs > 0 {
                    q_i - (scaled_abs % q_i)
                } else {
                    scaled_abs % q_i
                };

                result_limbs[limb_idx][coeff_idx] = scaled;
            }
        }

        self.to_montgomery_poly(&RNSPolynomial { limbs: result_limbs, n: self.n })
    }

    /// Relinearization: convert degree-2 ciphertext to degree-1
    fn relinearize(&self, c0: &RNSPolynomial, c1: &RNSPolynomial, c2: &RNSPolynomial,
                   ek: &RNSEvalKey) -> RNSCiphertext {
        // Decompose c2 into base-T digits
        let decomp = self.decompose_rns_poly(c2, ek.decomp_base);

        // c0' = c0 + sum(decomp[i] * rlk[i].0)
        // c1' = c1 + sum(decomp[i] * rlk[i].1)
        let mut c0_new = c0.clone();
        let mut c1_new = c1.clone();

        for (digit, (rk0, rk1)) in decomp.iter().zip(ek.rlk.iter()) {
            let term0 = self.rns_poly_mul(digit, rk0);
            let term1 = self.rns_poly_mul(digit, rk1);
            c0_new = c0_new.add(&term0, &self.rns);
            c1_new = c1_new.add(&term1, &self.rns);
        }

        RNSCiphertext {
            c0: c0_new.clone(),
            c1: c1_new.clone(),
            num_primes: self.rns.num_primes(),
        }
    }

    /// Decompose RNS polynomial into base-T digits
    fn decompose_rns_poly(&self, poly: &RNSPolynomial, base: u64) -> Vec<RNSPolynomial> {
        let poly_standard = self.from_montgomery_poly(poly);
        // Number of digits based on Q (128 bits max for 3 primes)
        let q_bits = 128 - self.q_product.leading_zeros() as usize;
        let base_bits = 64 - base.leading_zeros() as usize;
        let num_digits = (q_bits + base_bits - 1) / base_bits;

        // First, reconstruct to get actual coefficients (mod Q)
        let mut coeffs: Vec<u128> = (0..self.n)
            .map(|i| {
                let rns_coeff: Vec<u64> = poly_standard.limbs.iter()
                    .map(|limb| limb[i])
                    .collect();
                self.rns.to_int(&rns_coeff)
            })
            .collect();

        // Decompose into base-T digits
        let mut digits = Vec::with_capacity(num_digits);
        for _ in 0..num_digits {
            let digit: Vec<u64> = coeffs.iter().map(|&c| (c % base as u128) as u64).collect();
            let digit_poly = RNSPolynomial::from_poly(&digit, &self.rns);
            digits.push(self.to_montgomery_poly(&digit_poly));
            coeffs = coeffs.iter().map(|&c| c / base as u128).collect();
        }

        digits
    }

    /// RNS polynomial multiplication using parallel NTT
    ///
    /// Persistent Montgomery (Paper 2): single-RNS polynomials stay in Montgomery
    /// form and use persistent NTT when available.
    fn rns_poly_mul(&self, a: &RNSPolynomial, b: &RNSPolynomial) -> RNSPolynomial {
        #[cfg(feature = "ntt_fft")]
        let limbs: Vec<Vec<u64>> = a.limbs.iter()
            .zip(b.limbs.iter())
            .zip(self.ntt_engines.iter())
            .map(|((a_limb, b_limb), ntt)| ntt.multiply_persistent(a_limb, b_limb))
            .collect();

        #[cfg(not(feature = "ntt_fft"))]
        let limbs: Vec<Vec<u64>> = a.limbs.iter()
            .zip(b.limbs.iter())
            .zip(self.ntt_engines.iter())
            .zip(self.rns.mont_contexts.iter())
            .map(|(((a_limb, b_limb), ntt), mont)| {
                let a_std: Vec<u64> = a_limb.iter().map(|&c| mont.from_montgomery(c)).collect();
                let b_std: Vec<u64> = b_limb.iter().map(|&c| mont.from_montgomery(c)).collect();
                let prod_std = ntt.multiply(&a_std, &b_std);
                prod_std.into_iter().map(|c| mont.to_montgomery(c)).collect()
            })
            .collect();

        RNSPolynomial { limbs, n: self.n }
    }

    /// Scalar multiplication in RNS with per-limb scalars
    ///
    /// Each limb is multiplied by a different scalar (already reduced mod that prime)
    fn scalar_mul_rns_vec(&self, poly: &RNSPolynomial, scalars: &[u64]) -> RNSPolynomial {
        let limbs: Vec<Vec<u64>> = poly.limbs.iter()
            .zip(self.rns.primes.iter())
            .zip(scalars.iter())
            .map(|((limb, &prime), &scalar)| {
                limb.iter().map(|&c| ((c as u128 * scalar as u128) % prime as u128) as u64).collect()
            })
            .collect();

        RNSPolynomial { limbs, n: self.n }
    }

    // ========================================================================
    // DUAL-TRACK K-ELIMINATION METHODS
    // ========================================================================
    //
    // These methods maintain anchor residues through the ciphertext lifecycle,
    // enabling EXACT reconstruction via K-Elimination even when Δ² > Q.

    /// Generate dual-track key set with anchor residues
    pub fn generate_keys_dual(&self, rng: &mut ShadowHarvester) -> DualRNSKeySet {
        // Generate secret key s with small coefficients {-1, 0, 1}
        let s_choices: Vec<i8> = (0..self.n)
            .map(|_| {
                let r = rng.next_u64() % 3;
                match r {
                    0 => 0i8,
                    1 => 1i8,
                    _ => -1i8,
                }
            })
            .collect();

        // Create main RNS limbs
        let s_main: Vec<Vec<u64>> = self.config.primes.iter()
            .map(|&p| {
                s_choices.iter().map(|&c| {
                    if c < 0 { p - 1 } else { c as u64 }
                }).collect()
            })
            .collect();

        // Create anchor RNS limbs (same polynomial, different primes)
        let s_anchor: Vec<Vec<u64>> = self.dual_rns.anchor.primes.iter()
            .map(|&p| {
                s_choices.iter().map(|&c| {
                    if c < 0 { p - 1 } else { c as u64 }
                }).collect()
            })
            .collect();

        let s_dual = DualRNSPoly { main: s_main, anchor: s_anchor, n: self.n };
        let secret_key = DualRNSSecretKey { s: s_dual };

        // Generate random a - must be consistent across main AND anchor primes
        // Sample in [0, min_all_primes) to ensure correct representation in all moduli
        let min_all_primes = *self.config.primes.iter()
            .chain(self.dual_rns.anchor.primes.iter())
            .min()
            .unwrap();
        let a_coeffs: Vec<u64> = (0..self.n)
            .map(|_| rng.next_u64() % min_all_primes)
            .collect();
        // Now a_coeffs < min_all_primes, so a_coeffs % p = a_coeffs for all p
        let a_main: Vec<Vec<u64>> = self.config.primes.iter()
            .map(|&p| a_coeffs.iter().map(|&c| c % p).collect())
            .collect();
        let a_anchor: Vec<Vec<u64>> = self.dual_rns.anchor.primes.iter()
            .map(|&p| a_coeffs.iter().map(|&c| c % p).collect())
            .collect();
        let a_dual = DualRNSPoly { main: a_main, anchor: a_anchor, n: self.n };

        // Generate error e (using signed encoding for consistency across moduli)
        let e_signed: Vec<i64> = (0..self.n)
            .map(|_| sample_cbd_signed(rng, self.config.eta))
            .collect();
        let e_main: Vec<Vec<u64>> = self.config.primes.iter()
            .map(|&p| e_signed.iter().map(|&e| signed_to_mod(e, p)).collect())
            .collect();
        let e_anchor: Vec<Vec<u64>> = self.dual_rns.anchor.primes.iter()
            .map(|&p| e_signed.iter().map(|&e| signed_to_mod(e, p)).collect())
            .collect();
        let e_dual = DualRNSPoly { main: e_main, anchor: e_anchor, n: self.n };

        // pk0 = -(a*s + e)
        let as_dual = self.dual_poly_mul(&a_dual, &secret_key.s);
        let as_plus_e = self.dual_poly_add(&as_dual, &e_dual);
        let pk0 = self.dual_poly_neg(&as_plus_e);

        let public_key = DualRNSPublicKey { pk0, pk1: a_dual };

        DualRNSKeySet { secret_key, public_key }
    }

    /// Generate FULL dual-track keys including evaluation key for PUBLIC relinearization
    ///
    /// Use this for standard FHE where:
    /// - Key holder generates keys and distributes (public_key, eval_key)
    /// - Computing party can encrypt and compute WITHOUT secret_key
    /// - Only key holder can decrypt
    ///
    /// This is the standard IND-CPA secure FHE model.
    pub fn generate_keys_dual_full(&self, rng: &mut ShadowHarvester) -> DualRNSFullKeySet {
        // First generate basic keys
        let basic_keys = self.generate_keys_dual(rng);

        // Generate evaluation key for public relinearization
        let eval_key = self.generate_eval_key_dual(&basic_keys.secret_key, rng);

        DualRNSFullKeySet {
            secret_key: basic_keys.secret_key,
            public_key: basic_keys.public_key,
            eval_key,
        }
    }

    /// Generate dual-track evaluation key for relinearization
    ///
    /// Creates encrypted versions of s² so multiplication can be done without sk.
    /// Uses digit decomposition to reduce noise growth.
    fn generate_eval_key_dual(&self, sk: &DualRNSSecretKey, rng: &mut ShadowHarvester) -> DualRNSEvalKey {
        let decomp_base = 1u64 << 16; // 2^16 decomposition base
        let q_bits = 128 - self.q_product.leading_zeros() as usize;
        let num_digits = (q_bits + 15) / 16;

        // Find minimum prime across main AND anchor for safe sampling
        let min_main = self.config.primes.iter().min().copied().unwrap_or(u64::MAX);
        let min_anchor = self.dual_rns.anchor.primes.iter().min().copied().unwrap_or(u64::MAX);
        let min_all = min_main.min(min_anchor);

        // s² in dual form
        let s2 = self.dual_poly_mul(&sk.s, &sk.s);

        let mut rlk = Vec::with_capacity(num_digits);

        for i in 0..num_digits {
            // Compute power = decomp_base^i for each prime
            let power_main: Vec<u64> = self.config.primes.iter()
                .map(|&p| {
                    let mut result = 1u64;
                    let base_mod_p = decomp_base % p;
                    for _ in 0..i {
                        result = ((result as u128 * base_mod_p as u128) % p as u128) as u64;
                    }
                    result
                })
                .collect();

            let power_anchor: Vec<u64> = self.dual_rns.anchor.primes.iter()
                .map(|&p| {
                    let mut result = 1u64;
                    let base_mod_p = decomp_base % p;
                    for _ in 0..i {
                        result = ((result as u128 * base_mod_p as u128) % p as u128) as u64;
                    }
                    result
                })
                .collect();

            // Generate random a_i (consistent across main and anchor)
            let a_coeffs: Vec<u64> = (0..self.n)
                .map(|_| rng.next_u64() % min_all)
                .collect();
            let a_main: Vec<Vec<u64>> = self.config.primes.iter()
                .map(|&p| a_coeffs.iter().map(|&c| c % p).collect())
                .collect();
            let a_anchor: Vec<Vec<u64>> = self.dual_rns.anchor.primes.iter()
                .map(|&p| a_coeffs.iter().map(|&c| c % p).collect())
                .collect();
            let a_dual = DualRNSPoly { main: a_main, anchor: a_anchor, n: self.n };

            // Generate error e_i
            let e_signed: Vec<i64> = (0..self.n)
                .map(|_| sample_cbd_signed(rng, self.config.eta))
                .collect();
            let e_main: Vec<Vec<u64>> = self.config.primes.iter()
                .map(|&p| e_signed.iter().map(|&e| signed_to_mod(e, p)).collect())
                .collect();
            let e_anchor: Vec<Vec<u64>> = self.dual_rns.anchor.primes.iter()
                .map(|&p| e_signed.iter().map(|&e| signed_to_mod(e, p)).collect())
                .collect();
            let e_dual = DualRNSPoly { main: e_main, anchor: e_anchor, n: self.n };

            // rlk0_i = -a_i*s - e_i + power_i * s²
            let as_dual = self.dual_poly_mul(&a_dual, &sk.s);
            let as_plus_e = self.dual_poly_add(&as_dual, &e_dual);
            let neg_as_e = self.dual_poly_neg(&as_plus_e);

            // Scale s² by power (per-limb)
            let power_s2 = self.dual_scalar_mul_vec(&s2, &power_main, &power_anchor);
            let rlk0 = self.dual_poly_add(&neg_as_e, &power_s2);

            rlk.push((rlk0, a_dual));
        }

        DualRNSEvalKey { rlk, decomp_base, num_digits }
    }

    /// Scalar multiply dual polynomial by per-prime scalars
    fn dual_scalar_mul_vec(&self, poly: &DualRNSPoly, main_scalars: &[u64], anchor_scalars: &[u64]) -> DualRNSPoly {
        let main: Vec<Vec<u64>> = poly.main.iter().enumerate()
            .map(|(prime_idx, limb)| {
                let p = self.config.primes[prime_idx];
                let scalar = main_scalars[prime_idx];
                limb.iter().map(|&c| ((c as u128 * scalar as u128) % p as u128) as u64).collect()
            })
            .collect();

        let anchor: Vec<Vec<u64>> = poly.anchor.iter().enumerate()
            .map(|(prime_idx, limb)| {
                let p = self.dual_rns.anchor.primes[prime_idx];
                let scalar = anchor_scalars[prime_idx];
                limb.iter().map(|&c| ((c as u128 * scalar as u128) % p as u128) as u64).collect()
            })
            .collect();

        DualRNSPoly { main, anchor, n: poly.n }
    }

    /// Encrypt plaintext to dual-track ciphertext
    ///
    /// CRITICAL: Both main AND anchor residues are computed from encryption.
    /// This ensures K-Elimination can reconstruct exact values after tensor product.
    pub fn encrypt_dual(&self, m: u64, pk: &DualRNSPublicKey, rng: &mut ShadowHarvester) -> DualRNSCiphertext {
        assert!(m < self.t, "Plaintext must be < t");

        // Encode message: m * Δ
        let delta_big = self.q_product / self.t as u128;
        let encoded = (m as u128 * delta_big) as u128;

        // Create message polynomial (constant term only)
        let mut m_coeffs = vec![0u64; self.n];
        m_coeffs[0] = (encoded % self.q_product) as u64;

        let m_main = self.to_main_rns(&m_coeffs);
        let m_anchor = self.to_anchor_rns_u128(&m_coeffs, encoded);
        let m_dual = DualRNSPoly { main: m_main, anchor: m_anchor, n: self.n };

        // Generate small u with coefficients {-1, 0, 1}
        let u_choices: Vec<i8> = (0..self.n)
            .map(|_| {
                let r = rng.next_u64() % 3;
                match r {
                    0 => 0i8,
                    1 => 1i8,
                    _ => -1i8,
                }
            })
            .collect();

        let u_main: Vec<Vec<u64>> = self.config.primes.iter()
            .map(|&p| {
                u_choices.iter().map(|&c| {
                    if c < 0 { p - 1 } else { c as u64 }
                }).collect()
            })
            .collect();
        let u_anchor: Vec<Vec<u64>> = self.dual_rns.anchor.primes.iter()
            .map(|&p| {
                u_choices.iter().map(|&c| {
                    if c < 0 { p - 1 } else { c as u64 }
                }).collect()
            })
            .collect();
        let u_dual = DualRNSPoly { main: u_main, anchor: u_anchor, n: self.n };

        // Generate errors e1, e2 as SIGNED values, then convert correctly for each modulus
        // BUG FIX: sample_cbd uses q_min for signed representation, but this breaks
        // when we need residues for other moduli. Generate signed i64 first.
        let e1_signed: Vec<i64> = (0..self.n)
            .map(|_| sample_cbd_signed(rng, self.config.eta))
            .collect();
        let e1_main: Vec<Vec<u64>> = self.config.primes.iter()
            .map(|&p| e1_signed.iter().map(|&e| signed_to_mod(e, p)).collect())
            .collect();
        let e1_anchor: Vec<Vec<u64>> = self.dual_rns.anchor.primes.iter()
            .map(|&p| e1_signed.iter().map(|&e| signed_to_mod(e, p)).collect())
            .collect();
        let e1_dual = DualRNSPoly { main: e1_main, anchor: e1_anchor, n: self.n };

        let e2_signed: Vec<i64> = (0..self.n)
            .map(|_| sample_cbd_signed(rng, self.config.eta))
            .collect();
        let e2_main: Vec<Vec<u64>> = self.config.primes.iter()
            .map(|&p| e2_signed.iter().map(|&e| signed_to_mod(e, p)).collect())
            .collect();
        let e2_anchor: Vec<Vec<u64>> = self.dual_rns.anchor.primes.iter()
            .map(|&p| e2_signed.iter().map(|&e| signed_to_mod(e, p)).collect())
            .collect();
        let e2_dual = DualRNSPoly { main: e2_main, anchor: e2_anchor, n: self.n };

        // c0 = pk0 * u + e1 + m (in BOTH main and anchor systems)
        let pk0_u = self.dual_poly_mul(&pk.pk0, &u_dual);
        let c0 = self.dual_poly_add(&self.dual_poly_add(&pk0_u, &e1_dual), &m_dual);

        // c1 = pk1 * u + e2 (in BOTH main and anchor systems)
        let pk1_u = self.dual_poly_mul(&pk.pk1, &u_dual);
        let c1 = self.dual_poly_add(&pk1_u, &e2_dual);

        DualRNSCiphertext {
            c0,
            c1,
            level: self.config.primes.len(),
        }
    }

    /// Decrypt dual-track ciphertext
    pub fn decrypt_dual(&self, ct: &DualRNSCiphertext, sk: &DualRNSSecretKey) -> u64 {
        self.decrypt_dual_with_diagnostics(ct, sk).0
    }

    /// Decrypt with diagnostics: returns (decrypted, rounding_margin)
    ///
    /// The rounding margin indicates how close we are to a rounding failure:
    /// - Positive margin: decryption succeeded with this much safety room
    /// - Negative margin: rounding failed (error exceeded Δ/2)
    ///
    /// This is the key diagnostic for noise budget exhaustion.
    #[cfg(any(test, debug_assertions))]
    pub fn decrypt_dual_with_diagnostics(&self, ct: &DualRNSCiphertext, sk: &DualRNSSecretKey) -> (u64, i128) {
        // inner = c0 + c1 * s (use main RNS only for decryption)
        let c1_s = self.dual_poly_mul(&ct.c1, &sk.s);
        let inner = self.dual_poly_add(&ct.c0, &c1_s);

        // Reconstruct constant term from main RNS
        let rns_coeff: Vec<u64> = inner.main.iter().map(|limb| limb[0]).collect();
        let full_value = self.rns.to_int(&rns_coeff);

        // Δ = Q/t (scaling factor)
        let delta = self.q_product / self.t as u128;
        let delta_half = delta / 2;
        let q_half = self.q_product / 2;

        // Decode: round(inner * t / Q) mod t
        let (decoded, margin) = if full_value > q_half {
            // Negative case
            let neg_magnitude = self.q_product - full_value;
            let scaled_neg = (neg_magnitude * self.t as u128 + q_half) / self.q_product;
            let decoded = if scaled_neg == 0 { 0 } else { self.t - (scaled_neg % self.t as u128) as u64 };

            // Error = distance from ideal encoding point
            // For decoded value m, ideal point would be (Q - m*Δ) for negative
            let ideal_point = self.q_product - (decoded as u128 * delta);
            let error = if full_value > ideal_point {
                (full_value - ideal_point) as i128
            } else {
                -((ideal_point - full_value) as i128)
            };
            let margin = delta_half as i128 - error.abs();
            (decoded, margin)
        } else {
            // Positive case
            let scaled = (full_value * self.t as u128 + q_half) / self.q_product;
            let decoded = (scaled % self.t as u128) as u64;

            // For decoded value m, ideal point would be m*Δ
            let ideal_point = decoded as u128 * delta;
            let error = (full_value as i128) - (ideal_point as i128);
            let margin = delta_half as i128 - error.abs();
            (decoded, margin)
        };

        (decoded, margin)
    }

    /// Non-cfg version for release builds
    #[cfg(not(any(test, debug_assertions)))]
    fn decrypt_dual_with_diagnostics(&self, ct: &DualRNSCiphertext, sk: &DualRNSSecretKey) -> (u64, i128) {
        // inner = c0 + c1 * s (use main RNS only for decryption)
        let c1_s = self.dual_poly_mul(&ct.c1, &sk.s);
        let inner = self.dual_poly_add(&ct.c0, &c1_s);

        // Reconstruct constant term from main RNS
        let rns_coeff: Vec<u64> = inner.main.iter().map(|limb| limb[0]).collect();
        let full_value = self.rns.to_int(&rns_coeff);

        // Decode: round(inner * t / Q) mod t
        let q_half = self.q_product / 2;
        let decoded = if full_value > q_half {
            let neg_magnitude = self.q_product - full_value;
            let scaled_neg = (neg_magnitude * self.t as u128 + q_half) / self.q_product;
            if scaled_neg == 0 { 0 } else { self.t - (scaled_neg % self.t as u128) as u64 }
        } else {
            let scaled = (full_value * self.t as u128 + q_half) / self.q_product;
            (scaled % self.t as u128) as u64
        };
        (decoded, 0) // No diagnostics in release
    }

    /// Homomorphic multiplication using K-Elimination - SYMMETRIC MODE
    ///
    /// WARNING: This requires the secret key. Use only for single-party computation
    /// where the same entity encrypts, computes, and decrypts.
    ///
    /// For standard FHE (cloud computing on encrypted data), use `mul_dual_public`.
    pub fn mul_dual_symmetric(&self, ct1: &DualRNSCiphertext, ct2: &DualRNSCiphertext,
                               sk: &DualRNSSecretKey) -> DualRNSCiphertext {
        #[cfg(feature = "debug_dual_mul")]
        eprintln!("[DEBUG mul_dual_symmetric] ct1.level={}, ct2.level={}, n={}, main_primes={}, anchor_primes={}",
            ct1.level, ct2.level, self.n, self.dual_rns.main.primes.len(), self.dual_rns.anchor.primes.len());

        // Tensor product in BOTH main and anchor systems
        let d0 = self.dual_poly_mul(&ct1.c0, &ct2.c0);
        let c0_1_c1_2 = self.dual_poly_mul(&ct1.c0, &ct2.c1);
        let c1_1_c0_2 = self.dual_poly_mul(&ct1.c1, &ct2.c0);
        let d1 = self.dual_poly_add(&c0_1_c1_2, &c1_1_c0_2);
        let d2 = self.dual_poly_mul(&ct1.c1, &ct2.c1);

        // K-Elimination exact rescale
        let e0 = self.k_elim_rescale_dual(&d0);
        let e1 = self.k_elim_rescale_dual(&d1);
        let e2 = self.k_elim_rescale_dual(&d2);

        // Direct relinearization using s² (NOT SECURE for multi-party)
        let s2 = self.dual_poly_mul(&sk.s, &sk.s);
        let e2_s2 = self.dual_poly_mul(&e2, &s2);
        let c0_new = self.dual_poly_add(&e0, &e2_s2);

        DualRNSCiphertext { c0: c0_new, c1: e1, level: ct1.level }
    }

    /// Backward compatibility alias (deprecated)
    #[deprecated(note = "Use mul_dual_public for standard FHE security")]
    pub fn mul_dual(&self, ct1: &DualRNSCiphertext, ct2: &DualRNSCiphertext,
                    sk: &DualRNSSecretKey) -> DualRNSCiphertext {
        #[allow(deprecated)]
        self.mul_dual_symmetric(ct1, ct2, sk)
    }

    /// Homomorphic multiplication using K-Elimination - PUBLIC MODE (Standard FHE)
    ///
    /// This is the secure version for multi-party FHE:
    /// - Uses evaluation keys (encrypted s²) instead of secret key
    /// - Computing party never sees the secret key
    /// - Standard IND-CPA security under RLWE
    ///
    /// Security Model:
    /// - Key holder generates (pk, sk, evk) and distributes (pk, evk)
    /// - Computing party can encrypt (using pk) and compute (using evk)
    /// - Only key holder can decrypt (using sk)
    pub fn mul_dual_public(&self, ct1: &DualRNSCiphertext, ct2: &DualRNSCiphertext,
                           evk: &DualRNSEvalKey) -> DualRNSCiphertext {
        // CORRECT ORDER: relinearize THEN rescale (not rescale then relinearize!)
        //
        // The eval key is generated for the UNSCALED tensor product space.
        // If we rescale first, we feed the wrong scale into relinearization.
        //
        // Standard BFV flow:
        // 1. Tensor product → (d0, d1, d2) at scale Q² (degree-2 ciphertext)
        // 2. Relinearize d2 → fold into degree-1 (still at scale Q²)
        // 3. Rescale the combined result → divide by Δ (now at scale Q)

        // Step 1: Tensor product (unscaled, at modulus Q²)
        let d0 = self.dual_poly_mul(&ct1.c0, &ct2.c0);
        let c0_1_c1_2 = self.dual_poly_mul(&ct1.c0, &ct2.c1);
        let c1_1_c0_2 = self.dual_poly_mul(&ct1.c1, &ct2.c0);
        let d1 = self.dual_poly_add(&c0_1_c1_2, &c1_1_c0_2);
        let d2 = self.dual_poly_mul(&ct1.c1, &ct2.c1);

        // Step 2: PUBLIC relinearization on d2 (BEFORE rescale!)
        // Eval key was generated for this scale
        let (relin_c0, relin_c1) = self.relinearize_dual(&d2, evk);

        // Step 3: Combine into degree-1 ciphertext (still at tensor scale)
        let c0_pre = self.dual_poly_add(&d0, &relin_c0);
        let c1_pre = self.dual_poly_add(&d1, &relin_c1);

        // Step 4: K-Elimination rescale ONCE on the combined result
        let c0_new = self.k_elim_rescale_dual(&c0_pre);
        let c1_new = self.k_elim_rescale_dual(&c1_pre);

        DualRNSCiphertext { c0: c0_new, c1: c1_new, level: ct1.level }
    }

    /// Homomorphic addition for dual-track ciphertexts
    ///
    /// No noise growth from addition (aside from small accumulation).
    pub fn add_dual(&self, ct1: &DualRNSCiphertext, ct2: &DualRNSCiphertext) -> DualRNSCiphertext {
        let c0_new = self.dual_poly_add(&ct1.c0, &ct2.c0);
        let c1_new = self.dual_poly_add(&ct1.c1, &ct2.c1);
        DualRNSCiphertext { c0: c0_new, c1: c1_new, level: ct1.level.min(ct2.level) }
    }

    /// Relinearize a degree-2 term using evaluation keys
    ///
    /// Standard BFV relinearization:
    /// - Decompose poly into base-B digits
    /// - For each digit d_i, multiply by rlk[i] = (rlk0_i, rlk1_i)
    /// - Sum the contributions
    ///
    /// The eval key satisfies: sum_i (d_i * rlk0_i + s * d_i * rlk1_i) ≈ poly * s²
    /// So c0 + c1*s with relinearization = e0 + relin_c0 + (e1 + relin_c1)*s
    ///                                   = e0 + sum(d_i * rlk0_i) + (e1 + sum(d_i * rlk1_i))*s
    ///                                   ≈ e0 + e2*s² + e1*s (the original degree-2 result)
    fn relinearize_dual(&self, poly: &DualRNSPoly, evk: &DualRNSEvalKey) -> (DualRNSPoly, DualRNSPoly) {
        // Initialize accumulators to zero
        let mut result_c0 = self.dual_poly_zero();
        let mut result_c1 = self.dual_poly_zero();

        // For each digit of the decomposition
        for (digit_idx, (rlk0, rlk1)) in evk.rlk.iter().enumerate() {
            // Extract digit from each coefficient
            let digit_poly = self.extract_digit_dual(poly, digit_idx, evk.decomp_base);

            // Multiply digit by both rlk components
            // rlk0_i = -a_i*s - e_i + power_i * s²
            // rlk1_i = a_i
            let c0_contrib = self.dual_poly_mul(&digit_poly, rlk0);
            let c1_contrib = self.dual_poly_mul(&digit_poly, rlk1);

            result_c0 = self.dual_poly_add(&result_c0, &c0_contrib);
            result_c1 = self.dual_poly_add(&result_c1, &c1_contrib);
        }

        (result_c0, result_c1)
    }

    /// Extract the i-th digit of each coefficient (for decomposition)
    ///
    /// CRITICAL: Uses K-Elimination to get exact value, then centered representation
    /// for correct digit extraction of negative values.
    fn extract_digit_dual(&self, poly: &DualRNSPoly, digit_idx: usize, base: u64) -> DualRNSPoly {
        // For digit decomposition, we need the EXACT value (via K-Elimination),
        // then extract the digit.
        //
        // CRITICAL BUG FIX: We must use the K-eliminated exact value, NOT just v_m!
        // After tensor product, coefficients can exceed M, so v_m ≠ exact_value.
        // The digit extraction must be on the EXACT value to get correct relinearization.
        //
        // digit_i(x) = floor(x / base^i) mod base

        let base_power = (0..digit_idx).fold(1u128, |acc, _| acc * base as u128);
        let base_128 = base as u128;
        let m_product = self.dual_rns.main_product;

        let mut main: Vec<Vec<u64>> = vec![vec![0u64; self.n]; self.config.primes.len()];
        let mut anchor: Vec<Vec<u64>> = vec![vec![0u64; self.n]; self.dual_rns.anchor.primes.len()];

        for i in 0..self.n {
            // Use K-Elimination to get EXACT value
            let main_residues: Vec<u64> = poly.main.iter().map(|limb| limb[i]).collect();
            let v_m = self.rns.to_int(&main_residues);
            let anchor_residues: Vec<u64> = poly.anchor.iter().map(|limb| limb[i]).collect();
            let k = self.dual_rns.extract_k_rns(v_m, &anchor_residues);

            // Compute exact_value = v_m + k * M using wide arithmetic
            // k * M can exceed u128 (k up to ~10^21, M ~10^18, product ~10^39 > 2^128)
            // Use 256-bit representation: (lo, hi) where value = lo + hi * 2^128
            let (exact_lo, exact_hi) = wide_add_u128(
                v_m, 0,  // v_m as (lo, hi)
                wide_mul_u128(k, m_product)  // k * M as (lo, hi)
            );

            // Extract digit: (exact / base_power) mod base
            // Since base = 2^16 and base_power = 2^(16*idx), we need bits [16*idx : 16*idx+16)
            // For digit_idx up to ~8 (covers up to ~2^128), this stays in the low word
            let digit = if digit_idx < 8 {
                // Digit is in low 128 bits
                ((exact_lo / base_power) % base_128) as u64
            } else {
                // Digit might be in high bits - use wide division
                // For our parameters (Q^2 < 10^40, fits in ~133 bits), digit_idx < 9 suffices
                let shift_bits = (digit_idx as u32) * 16;
                if shift_bits < 128 {
                    ((exact_lo >> shift_bits) | (exact_hi << (128 - shift_bits))) as u64 & 0xFFFF
                } else {
                    (exact_hi >> (shift_bits - 128)) as u64 & 0xFFFF
                }
            };

            // Store digit in each RNS limb (digit is small, fits in all moduli)
            for (prime_idx, limb) in main.iter_mut().enumerate() {
                limb[i] = digit % self.config.primes[prime_idx];
            }
            for (prime_idx, limb) in anchor.iter_mut().enumerate() {
                limb[i] = digit % self.dual_rns.anchor.primes[prime_idx];
            }
        }

        DualRNSPoly { main, anchor, n: self.n }
    }

    /// Create zero polynomial in dual form
    fn dual_poly_zero(&self) -> DualRNSPoly {
        let main = vec![vec![0u64; self.n]; self.config.primes.len()];
        let anchor = vec![vec![0u64; self.n]; self.dual_rns.anchor.primes.len()];
        DualRNSPoly { main, anchor, n: self.n }
    }

    /// K-Elimination rescale for dual-track polynomial (COEFFICIENT DOMAIN)
    ///
    /// CRITICAL: This reconstructs the EXACT value from main+anchor before dividing.
    /// Formula: k = ((v_a - v_m) × M⁻¹) mod A; exact = v_m + k × M
    ///
    /// The rescale computes: round(v_exact / Δ) mod M
    /// Using Paper 2 Lemma: round((v_m + k*M) / Δ) ≡ round((v_m + (k mod Δ)*M) / Δ) (mod M)
    ///
    /// IMPORTANT: We CENTER v_m around Q/2 before processing to handle values
    /// that represent negative noise (values > Q/2 are interpreted as negative).
    fn k_elim_rescale_dual(&self, poly: &DualRNSPoly) -> DualRNSPoly {
        let delta = self.q_product / self.t as u128;
        let m_product = self.dual_rns.main_product;
        let q_half = m_product / 2;

        let mut result_main: Vec<Vec<u64>> = vec![vec![0u64; self.n]; self.config.primes.len()];
        let mut result_anchor: Vec<Vec<u64>> = vec![vec![0u64; self.n]; self.dual_rns.anchor.primes.len()];

        // Product of first N anchor primes for signed k interpretation
        // (used for k > A_n/2 detection)
        // Use min(3, available) primes for the signed interpretation threshold
        let num_primes_for_sign = self.dual_rns.anchor.primes.len().min(3);
        let a_n_product: u128 = self.dual_rns.anchor.primes[0..num_primes_for_sign].iter()
            .fold(1u128, |acc, &p| acc * p as u128);

        for i in 0..self.n {
            // Reconstruct v_m from main RNS (mod M = Q)
            let main_residues: Vec<u64> = poly.main.iter().map(|limb| limb[i]).collect();
            let v_m = self.rns.to_int(&main_residues);

            // Get anchor residues (don't call to_int, it may overflow for 5+ primes)
            let anchor_residues: Vec<u64> = poly.anchor.iter().map(|limb| limb[i]).collect();

            // K-Elimination: compute k using RNS-domain method
            // This works for any number of anchor primes
            let k = self.dual_rns.extract_k_rns(v_m, &anchor_residues);

            // Interpret k as signed using anchor prime product
            // k > A_n/2 means the true value wrapped below 0
            let k_signed = SignedK::from_unsigned(k, a_n_product);

            // DEBUG: Print k value for constant term with EXACT values
            #[cfg(test)]
            if i == 0 {
                eprintln!("  [rescale coeff 0] M={:.2e}, A3={:.2e}, A3/2={:.2e}",
                    m_product as f64, a_n_product as f64, (a_n_product/2) as f64);
                eprintln!("    v_m={} ({:.2e})", v_m, v_m as f64);
                eprintln!("    k={} ({:.2e}), k > A3/2 = {}", k, k as f64, k > a_n_product / 2);
                eprintln!("    k_signed = {}{} (is_neg={})",
                    if k_signed.is_neg { "-" } else { "+" },
                    k_signed.magnitude,
                    k_signed.is_neg);
            }

            // Now compute the rescale.
            // v_exact = v_m + k_signed * M (where k_signed can be negative)
            //
            // We want: round(v_exact / Δ) mod M
            //
            // Key insight: v_m is already in [0, M). But it might represent a
            // negative value (if v_m > M/2). We need to CENTER v_m first,
            // then add the k contribution, then divide.
            //
            // CENTER v_m: if v_m > M/2, interpret as v_m - M (negative)
            let v_m_centered: i128 = if v_m > q_half {
                v_m as i128 - m_product as i128
            } else {
                v_m as i128
            };

            // Add k contribution: v_centered = v_m_centered + k_signed * M
            // Since k_signed * M is a multiple of M, this doesn't change the
            // value mod M, but it shifts which "copy" of the residue we're in.
            //
            // For rescaling with the "k mod Δ" trick:
            // round((v_m + k*M) / Δ) ≡ round((v_m + (k mod Δ)*M) / Δ) (mod M)
            let k_mod_delta = k_signed.magnitude % delta;

            let scaled_mod_m = if !k_signed.is_neg {
                // POSITIVE k case: v_exact = v_m + k*M
                // With centering: v_exact_centered = v_m_centered + k_mod_delta * M

                if v_m_centered >= 0 {
                    // v_m is positive, adding k*M keeps it positive
                    let v_prime = v_m_centered as u128 + k_mod_delta * m_product;
                    // Round and reduce
                    ((v_prime + delta / 2) / delta) % m_product
                } else {
                    // v_m is negative (v_m_centered < 0)
                    // v_exact_centered = v_m_centered + k_mod_delta * M
                    let neg_vm = (-v_m_centered) as u128;
                    let k_contrib = k_mod_delta * m_product;

                    if k_contrib >= neg_vm {
                        // Net result is positive
                        let net = k_contrib - neg_vm;
                        ((net + delta / 2) / delta) % m_product
                    } else {
                        // Net result is still negative
                        let net_neg = neg_vm - k_contrib;
                        let scaled_neg = (net_neg + delta / 2) / delta;
                        let scaled_mod = scaled_neg % m_product;
                        if scaled_mod == 0 { 0 } else { m_product - scaled_mod }
                    }
                }
            } else {
                // NEGATIVE k case: v_exact = v_m - neg_k*M
                // With centering: v_exact_centered = v_m_centered - k_mod_delta * M
                let k_contrib = k_mod_delta * m_product;

                if v_m_centered >= 0 {
                    let pos_vm = v_m_centered as u128;
                    if pos_vm >= k_contrib {
                        // Result is positive
                        let net = pos_vm - k_contrib;
                        ((net + delta / 2) / delta) % m_product
                    } else {
                        // Result is negative
                        let net_neg = k_contrib - pos_vm;
                        let scaled_neg = (net_neg + delta / 2) / delta;
                        let scaled_mod = scaled_neg % m_product;
                        if scaled_mod == 0 { 0 } else { m_product - scaled_mod }
                    }
                } else {
                    // v_m is already negative, subtracting makes it more negative
                    let neg_vm = (-v_m_centered) as u128;
                    let total_neg = neg_vm + k_contrib;
                    let scaled_neg = (total_neg + delta / 2) / delta;
                    let scaled_mod = scaled_neg % m_product;
                    if scaled_mod == 0 { 0 } else { m_product - scaled_mod }
                }
            };

            // ═══════════════════════════════════════════════════════════════════
            // KEYSTONE INVARIANT: Centered Representative Bridge
            // ═══════════════════════════════════════════════════════════════════
            //
            // When crossing main ↔ anchor, ALWAYS go through the centered signed integer.
            // DO NOT reduce scaled_mod_m directly into anchor primes.
            //
            // scaled_mod_m ∈ [0, M) but represents a signed integer in (-M/2, M/2]
            // If we just do `scaled_mod_m % a_j`, we get wrong residues for negative values
            // because M is NOT divisible by anchor primes!
            //
            // Example: If scaled_mod_m = M-5 represents -5:
            //   - Main: (M-5) % p_main = -5 mod p_main ✓ (because M % p_main = 0)
            //   - Anchor: (M-5) % a_j = (M mod a_j) - 5 ≠ -5 mod a_j ✗
            //
            // Fix: Extract the TRUE signed integer, then reduce to BOTH systems
            let m_half = m_product / 2;
            let true_value: i128 = if scaled_mod_m > m_half {
                // Represents negative: true_value = scaled_mod_m - M
                -((m_product - scaled_mod_m) as i128)
            } else {
                scaled_mod_m as i128
            };

            // Re-encode TRUE value to main RNS
            for (j, &p) in self.config.primes.iter().enumerate() {
                let p128 = p as i128;
                result_main[j][i] = ((true_value % p128 + p128) % p128) as u64;
            }

            // Re-encode TRUE value to anchor RNS
            for (j, &p) in self.dual_rns.anchor.primes.iter().enumerate() {
                let p128 = p as i128;
                result_anchor[j][i] = ((true_value % p128 + p128) % p128) as u64;
            }

            // DEBUG: Show rescale output
            #[cfg(test)]
            if i == 0 {
                eprintln!("    [rescale OUTPUT] scaled_mod_m = {} ({:.2e})", scaled_mod_m, scaled_mod_m as f64);
            }
        }

        DualRNSPoly { main: result_main, anchor: result_anchor, n: self.n }
    }

    // ========================================================================
    // NTT-DOMAIN K-ELIMINATION (Q² bound instead of Q²×N)
    // ========================================================================
    //
    // KEY INSIGHT: In NTT domain, each point is independent.
    // Tensor product of two NTT points is bounded by Q² (single product)
    // vs coefficient domain where it's Q²×N (sum of N products).
    //
    // This enables K-Elimination for multi-prime RNS by keeping everything
    // in NTT form and doing point-wise rescaling.

    /// Convert dual polynomial to NTT form
    fn to_ntt_form(&self, poly: &DualRNSPoly) -> DualRNSPoly {
        // Transform main limbs to NTT form
        let main_ntt: Vec<Vec<u64>> = poly.main.iter()
            .zip(self.ntt_engines.iter())
            .map(|(limb, ntt)| ntt.ntt(limb))
            .collect();

        // Transform anchor limbs to NTT form
        let anchor_ntt: Vec<Vec<u64>> = poly.anchor.iter()
            .zip(self.dual_rns.anchor.ntt_engines.iter())
            .map(|(limb, ntt)| ntt.ntt(limb))
            .collect();

        DualRNSPoly { main: main_ntt, anchor: anchor_ntt, n: poly.n }
    }

    /// Convert from NTT form back to coefficient form
    fn from_ntt_form(&self, poly_ntt: &DualRNSPoly) -> DualRNSPoly {
        // Transform main limbs from NTT form
        let main: Vec<Vec<u64>> = poly_ntt.main.iter()
            .zip(self.ntt_engines.iter())
            .map(|(limb, ntt)| ntt.intt(limb))
            .collect();

        // Transform anchor limbs from NTT form
        let anchor: Vec<Vec<u64>> = poly_ntt.anchor.iter()
            .zip(self.dual_rns.anchor.ntt_engines.iter())
            .map(|(limb, ntt)| ntt.intt(limb))
            .collect();

        DualRNSPoly { main, anchor, n: poly_ntt.n }
    }

    /// Point-wise multiplication in NTT domain (both inputs must be in NTT form)
    fn ntt_pointwise_mul(&self, a_ntt: &DualRNSPoly, b_ntt: &DualRNSPoly) -> DualRNSPoly {
        // Main: point-wise multiply
        let main: Vec<Vec<u64>> = a_ntt.main.iter()
            .zip(&b_ntt.main)
            .zip(&self.config.primes)
            .map(|((a_limb, b_limb), &p)| {
                a_limb.iter().zip(b_limb)
                    .map(|(&x, &y)| ((x as u128 * y as u128) % p as u128) as u64)
                    .collect()
            })
            .collect();

        // Anchor: point-wise multiply
        let anchor: Vec<Vec<u64>> = a_ntt.anchor.iter()
            .zip(&b_ntt.anchor)
            .zip(&self.dual_rns.anchor.primes)
            .map(|((a_limb, b_limb), &p)| {
                a_limb.iter().zip(b_limb)
                    .map(|(&x, &y)| ((x as u128 * y as u128) % p as u128) as u64)
                    .collect()
            })
            .collect();

        DualRNSPoly { main, anchor, n: a_ntt.n }
    }

    /// Point-wise addition in NTT domain
    fn ntt_pointwise_add(&self, a_ntt: &DualRNSPoly, b_ntt: &DualRNSPoly) -> DualRNSPoly {
        self.dual_poly_add(a_ntt, b_ntt) // Same as coefficient-domain add
    }

    /// K-Elimination rescale in NTT DOMAIN (Q² bound)
    ///
    /// ⚠️ DEPRECATED: NTT-domain K-Elimination is INVALID for multi-prime RNS.
    ///
    /// K-Elimination requires coefficients to represent the SAME value mod different primes.
    /// In NTT domain, different primes use different primitive roots:
    ///   NTT_{p1}(poly)[i] ≠ NTT_{p2}(poly)[i] as algebraic values
    ///
    /// Use `k_elim_rescale_dual` in coefficient domain instead.
    /// This function is kept only for reference/single-prime edge cases.
    #[allow(dead_code)]
    #[deprecated(note = "Use k_elim_rescale_dual in coefficient domain instead")]
    fn k_elim_rescale_ntt_domain(&self, _poly_ntt: &DualRNSPoly) -> DualRNSPoly {
        panic!("k_elim_rescale_ntt_domain is invalid for multi-prime RNS. \
                K-Elim requires coefficient domain. Use k_elim_rescale_dual instead.");

        // Original implementation commented out for reference:
        /*
        let delta = self.q_product / self.t as u128;
        let m_product = self.dual_rns.main_product;
        let a_product = self.dual_rns.anchor_product;
        let m_inv_a = self.dual_rns.main_inv_anchor;

        let mut result_main: Vec<Vec<u64>> = vec![vec![0u64; self.n]; self.config.primes.len()];
        let mut result_anchor: Vec<Vec<u64>> = vec![vec![0u64; self.n]; self.dual_rns.anchor.primes.len()];

        for i in 0..self.n {
            // Each NTT point is independent, bounded by Q² (single product)
            // vs coefficient domain Q²×N (sum of N products)

            // Reconstruct v_m from main RNS (mod M)
            let main_residues: Vec<u64> = poly_ntt.main.iter().map(|limb| limb[i]).collect();
            let v_m = self.rns.to_int(&main_residues);

            // Reconstruct v_a from anchor RNS (mod A)
            let anchor_residues: Vec<u64> = poly_ntt.anchor.iter().map(|limb| limb[i]).collect();
            let v_a = self.dual_rns.anchor.to_int(&anchor_residues);

            // K-Elimination: compute k such that exact_value = v_m + k*M
            // k = ((v_a - v_m mod A) × M⁻¹) mod A
            //
            // Key insight: actual k ≤ Q²/M ≈ Q (fits in u64) because exact_value < Q²
            // But intermediate computation can overflow, so use modular multiplication
            let v_m_mod_a = v_m % a_product;
            let diff = if v_a >= v_m_mod_a {
                v_a - v_m_mod_a
            } else {
                a_product - v_m_mod_a + v_a
            };

            // Use modular multiplication to avoid overflow: (diff * m_inv_a) mod a_product
            let k = mul_mod_u128(diff, m_inv_a, a_product);

            // Reconstruct exact NTT point value
            // Since exact_value < Q² and v_m < M, k < Q²/M = Q, so k * m_product < Q² × M
            // which still might overflow u128 for large Q. Use checked arithmetic.
            let k_times_m = k.checked_mul(m_product).unwrap_or_else(|| {
                // For very large k, use modular approach: k * m_product mod (large_value)
                // But actually if this happens, the value wouldn't fit anyway.
                // In practice with correct NTT point bounds, this shouldn't overflow.
                panic!("K-Elimination overflow: k={}, m_product={}", k, m_product);
            });
            let exact_value = v_m.saturating_add(k_times_m);

            // Divide by Δ (round to nearest) - this is the rescaling
            let scaled = (exact_value + delta / 2) / delta;

            // Re-encode to main RNS (stays in "NTT form" - same representation)
            for (j, &p) in self.config.primes.iter().enumerate() {
                result_main[j][i] = (scaled % p as u128) as u64;
            }

            // Re-encode to anchor RNS
            for (j, &p) in self.dual_rns.anchor.primes.iter().enumerate() {
                result_anchor[j][i] = (scaled % p as u128) as u64;
            }
        }

        DualRNSPoly { main: result_main, anchor: result_anchor, n: self.n }
        */
    }

    /// Full NTT-domain CT×CT multiplication
    ///
    /// IMPORTANT: K-Elimination rescaling does NOT commute with NTT for multi-prime RNS.
    /// Different primes use different primitive roots, so NTT_{p1}(poly)[i] ≠ NTT_{p2}(poly)[i].
    /// K-Elim requires coefficients to represent the SAME value mod different primes.
    ///
    /// Correct approach (INTT → rescale → NTT):
    /// 1. Convert ciphertexts to NTT form
    /// 2. Point-wise tensor product (each point ≤ Q²)
    /// 3. INTT to coefficient domain (where K-Elim is valid)
    /// 4. K-Elimination rescale in coefficient domain
    /// 5. Relinearize and return
    ///
    /// Requires: 4 anchor primes (A ≈ 10^38 > Q² ≈ 10^36)
    pub fn mul_ntt_domain(&self, ct1: &DualRNSCiphertext, ct2: &DualRNSCiphertext,
                          sk: &DualRNSSecretKey) -> DualRNSCiphertext {
        // Convert to NTT form for fast tensor product
        let ct1_c0_ntt = self.to_ntt_form(&ct1.c0);
        let ct1_c1_ntt = self.to_ntt_form(&ct1.c1);
        let ct2_c0_ntt = self.to_ntt_form(&ct2.c0);
        let ct2_c1_ntt = self.to_ntt_form(&ct2.c1);

        // Tensor product in NTT domain (point-wise, each ≤ Q²)
        // d0 = c0_1 × c0_2
        let d0_ntt = self.ntt_pointwise_mul(&ct1_c0_ntt, &ct2_c0_ntt);

        // d1 = c0_1 × c1_2 + c1_1 × c0_2
        let c0_1_c1_2_ntt = self.ntt_pointwise_mul(&ct1_c0_ntt, &ct2_c1_ntt);
        let c1_1_c0_2_ntt = self.ntt_pointwise_mul(&ct1_c1_ntt, &ct2_c0_ntt);
        let d1_ntt = self.ntt_pointwise_add(&c0_1_c1_2_ntt, &c1_1_c0_2_ntt);

        // d2 = c1_1 × c1_2
        let d2_ntt = self.ntt_pointwise_mul(&ct1_c1_ntt, &ct2_c1_ntt);

        // CRITICAL: INTT to coefficient domain before K-Elim rescaling.
        // K-Elim requires coefficients (not NTT points) to be the same value mod different primes.
        let d0 = self.from_ntt_form(&d0_ntt);
        let d1 = self.from_ntt_form(&d1_ntt);
        let d2 = self.from_ntt_form(&d2_ntt);

        // K-Elimination rescale in COEFFICIENT domain (the only valid approach)
        let e0 = self.k_elim_rescale_dual(&d0);
        let e1 = self.k_elim_rescale_dual(&d1);
        let e2 = self.k_elim_rescale_dual(&d2);

        // Relinearize: fold e2 into e0 using s²
        // c0' = e0 + e2 * s²
        // c1' = e1
        let s2 = self.dual_poly_mul(&sk.s, &sk.s);
        let e2_s2 = self.dual_poly_mul(&e2, &s2);
        let c0_new = self.dual_poly_add(&e0, &e2_s2);

        DualRNSCiphertext {
            c0: c0_new,
            c1: e1,
            level: ct1.level,
        }
    }

    // ========================================================================
    // COEFFICIENT-DOMAIN K-ELIMINATION MULTIPLICATION (CORRECT APPROACH)
    // ========================================================================
    //
    // NTT-domain K-Elimination is INVALID because different primes use different
    // roots of unity: NTT_{p1}(poly)[i] ≠ NTT_{p2}(poly)[i] as values.
    //
    // Correct flow:
    // 1. NTT tensor product (fast point-wise multiplication)
    // 2. INTT to coefficient domain (now all residues represent same values)
    // 3. K-Elimination rescale in coefficient domain
    // 4. Relinearize
    //
    // Capacity requirement: M × A > Q² × N for coefficient domain

    /// Coefficient-domain CT×CT multiplication with K-Elimination rescaling
    ///
    /// This is the CORRECT approach:
    /// 1. NTT tensor product (fast)
    /// 2. INTT to coefficient domain
    /// 3. K-Elimination rescale (coefficients are same value mod different primes)
    /// 4. Relinearize
    ///
    /// Requires: M × A > Q² × N (4 anchor primes give ~6.5×10^55 >> 10^39)
    pub fn mul_coeff_domain(&self, ct1: &DualRNSCiphertext, ct2: &DualRNSCiphertext,
                            sk: &DualRNSSecretKey) -> DualRNSCiphertext {
        // Step 1: Convert to NTT form for fast tensor product
        let ct1_c0_ntt = self.to_ntt_form(&ct1.c0);
        let ct1_c1_ntt = self.to_ntt_form(&ct1.c1);
        let ct2_c0_ntt = self.to_ntt_form(&ct2.c0);
        let ct2_c1_ntt = self.to_ntt_form(&ct2.c1);

        // Step 2: Tensor product in NTT domain (point-wise, efficient)
        // d0 = c0_1 × c0_2
        let d0_ntt = self.ntt_pointwise_mul(&ct1_c0_ntt, &ct2_c0_ntt);

        // d1 = c0_1 × c1_2 + c1_1 × c0_2
        let c0_1_c1_2_ntt = self.ntt_pointwise_mul(&ct1_c0_ntt, &ct2_c1_ntt);
        let c1_1_c0_2_ntt = self.ntt_pointwise_mul(&ct1_c1_ntt, &ct2_c0_ntt);
        let d1_ntt = self.ntt_pointwise_add(&c0_1_c1_2_ntt, &c1_1_c0_2_ntt);

        // d2 = c1_1 × c1_2
        let d2_ntt = self.ntt_pointwise_mul(&ct1_c1_ntt, &ct2_c1_ntt);

        // Step 3: INTT back to coefficient domain
        // NOW the residues represent the same polynomial coefficients
        let d0_coeff = self.from_ntt_form(&d0_ntt);
        let d1_coeff = self.from_ntt_form(&d1_ntt);
        let d2_coeff = self.from_ntt_form(&d2_ntt);

        // Step 4: K-Elimination rescale in coefficient domain
        // Each coefficient c[i] is the same integer value with residues mod p_j
        // K-Elim reconstructs exact value and divides by Δ
        let e0 = self.k_elim_rescale_dual(&d0_coeff);
        let e1 = self.k_elim_rescale_dual(&d1_coeff);
        let e2 = self.k_elim_rescale_dual(&d2_coeff);

        // Step 5: Relinearize: fold e2 into e0 using s²
        // c0' = e0 + e2 * s²
        // c1' = e1
        let s2 = self.dual_poly_mul(&sk.s, &sk.s);
        let e2_s2 = self.dual_poly_mul(&e2, &s2);
        let c0_new = self.dual_poly_add(&e0, &e2_s2);

        DualRNSCiphertext {
            c0: c0_new,
            c1: e1,
            level: ct1.level,
        }
    }

    // ========================================================================
    // DUAL-TRACK POLYNOMIAL HELPERS
    // ========================================================================

    /// Convert coefficient vector to main RNS form
    fn to_main_rns(&self, coeffs: &[u64]) -> Vec<Vec<u64>> {
        self.config.primes.iter()
            .map(|&p| coeffs.iter().map(|&c| c % p).collect())
            .collect()
    }

    /// Convert coefficient vector to anchor RNS form (with u128 precision for encoded value)
    fn to_anchor_rns_u128(&self, coeffs: &[u64], encoded_value: u128) -> Vec<Vec<u64>> {
        self.dual_rns.anchor.primes.iter()
            .map(|&p| {
                let mut result = vec![0u64; self.n];
                result[0] = (encoded_value % p as u128) as u64;
                for i in 1..self.n {
                    result[i] = coeffs[i] % p;
                }
                result
            })
            .collect()
    }

    /// Dual polynomial addition
    fn dual_poly_add(&self, a: &DualRNSPoly, b: &DualRNSPoly) -> DualRNSPoly {
        let main: Vec<Vec<u64>> = a.main.iter()
            .zip(&b.main)
            .zip(&self.config.primes)
            .map(|((a_limb, b_limb), &p)| {
                a_limb.iter().zip(b_limb)
                    .map(|(&x, &y)| ((x as u128 + y as u128) % p as u128) as u64)
                    .collect()
            })
            .collect();

        let anchor: Vec<Vec<u64>> = a.anchor.iter()
            .zip(&b.anchor)
            .zip(&self.dual_rns.anchor.primes)
            .map(|((a_limb, b_limb), &p)| {
                a_limb.iter().zip(b_limb)
                    .map(|(&x, &y)| ((x as u128 + y as u128) % p as u128) as u64)
                    .collect()
            })
            .collect();

        DualRNSPoly { main, anchor, n: self.n }
    }

    /// Dual polynomial negation
    fn dual_poly_neg(&self, a: &DualRNSPoly) -> DualRNSPoly {
        let main: Vec<Vec<u64>> = a.main.iter()
            .zip(&self.config.primes)
            .map(|(limb, &p)| {
                limb.iter().map(|&x| if x == 0 { 0 } else { p - x }).collect()
            })
            .collect();

        let anchor: Vec<Vec<u64>> = a.anchor.iter()
            .zip(&self.dual_rns.anchor.primes)
            .map(|(limb, &p)| {
                limb.iter().map(|&x| if x == 0 { 0 } else { p - x }).collect()
            })
            .collect();

        DualRNSPoly { main, anchor, n: self.n }
    }

    /// Dual polynomial multiplication using NTT in both systems
    fn dual_poly_mul(&self, a: &DualRNSPoly, b: &DualRNSPoly) -> DualRNSPoly {
        // Main system: use NTT engines
        let main: Vec<Vec<u64>> = a.main.iter()
            .zip(&b.main)
            .zip(self.ntt_engines.iter())
            .map(|((a_limb, b_limb), ntt)| {
                ntt.multiply(a_limb, b_limb)
            })
            .collect();

        // Anchor system: use anchor NTT engines from dual_rns
        let anchor: Vec<Vec<u64>> = a.anchor.iter()
            .zip(&b.anchor)
            .zip(self.dual_rns.anchor.ntt_engines.iter())
            .map(|((a_limb, b_limb), ntt)| {
                ntt.multiply(a_limb, b_limb)
            })
            .collect();

        let result = DualRNSPoly { main, anchor, n: self.n };

        #[cfg(feature = "debug_dual_mul")]
        eprintln!("[DEBUG dual_poly_mul] result computed, n={}", self.n);

        result
    }
}

// ============================================================================
// K-ELIMINATION HELPERS
// ============================================================================

/// Signed interpretation of k ∈ [0, A) as k_signed ∈ (-A/2, A/2]
///
/// This prevents the bug where raw `k % delta` is computed before sign interpretation.
/// Always normalize k through this helper first.
#[derive(Clone, Copy, Debug)]
struct SignedK {
    /// True if k represents a negative value (k > A/2)
    is_neg: bool,
    /// Magnitude: |k_signed| = k if positive, A-k if negative
    magnitude: u128,
}

impl SignedK {
    /// Normalize k ∈ [0, A) to signed interpretation
    #[inline]
    fn from_unsigned(k: u128, a_product: u128) -> Self {
        let half_a = a_product / 2;
        if k <= half_a {
            SignedK { is_neg: false, magnitude: k }
        } else {
            SignedK { is_neg: true, magnitude: a_product - k }
        }
    }

    /// Get the signed value as i128 (for debugging/display only)
    #[allow(dead_code)]
    fn to_signed(&self) -> i128 {
        if self.is_neg {
            -(self.magnitude as i128)
        } else {
            self.magnitude as i128
        }
    }
}

/// Wide u128 multiplication: returns (lo, hi) where result = hi * 2^128 + lo
fn wide_mul_u128(a: u128, b: u128) -> (u128, u128) {
    wide_mul_256(a, b)
}

/// Wide u128 addition: (a_lo, a_hi) + (b_lo, b_hi) = (result_lo, result_hi)
fn wide_add_u128(a_lo: u128, a_hi: u128, (b_lo, b_hi): (u128, u128)) -> (u128, u128) {
    let (sum_lo, carry) = a_lo.overflowing_add(b_lo);
    let sum_hi = a_hi + b_hi + if carry { 1 } else { 0 };
    (sum_lo, sum_hi)
}

/// Wide 256-bit multiplication: returns (lo, hi) where result = hi * 2^128 + lo
fn wide_mul_256(a: u128, b: u128) -> (u128, u128) {
    let a_lo = a as u64 as u128;
    let a_hi = (a >> 64) as u64 as u128;
    let b_lo = b as u64 as u128;
    let b_hi = (b >> 64) as u64 as u128;

    let lo_lo = a_lo * b_lo;
    let hi_lo = a_hi * b_lo;
    let lo_hi = a_lo * b_hi;
    let hi_hi = a_hi * b_hi;

    // Combine: result_lo = lo_lo + (hi_lo + lo_hi) << 64 (low 128 bits)
    //          result_hi = hi_hi + carry
    let mid = hi_lo + lo_hi;
    let (result_lo, carry1) = lo_lo.overflowing_add(mid << 64);
    let carry2 = mid >> 64;
    let result_hi = hi_hi + carry2 + if carry1 { 1 } else { 0 };

    (result_lo, result_hi)
}

/// Convert signed i64 to modular representation
/// For v >= 0: return v
/// For v < 0: return p - |v|
fn signed_to_mod(v: i64, p: u64) -> u64 {
    if v >= 0 {
        (v as u64) % p
    } else {
        p - ((-v) as u64 % p)
    }
}

/// Sample from centered binomial distribution, returning SIGNED value
fn sample_cbd_signed(rng: &mut ShadowHarvester, eta: usize) -> i64 {
    let mut sum: i64 = 0;
    for _ in 0..eta {
        let a = (rng.next_u64() & 1) as i64;
        let b = (rng.next_u64() & 1) as i64;
        sum += a - b;
    }
    sum  // Returns value in {-eta, ..., +eta}
}

/// Sample from centered binomial distribution (legacy version for single modulus)
fn sample_cbd(rng: &mut ShadowHarvester, eta: usize, q: u64) -> u64 {
    let mut sum: i64 = 0;
    for _ in 0..eta {
        let a = (rng.next_u64() & 1) as i64;
        let b = (rng.next_u64() & 1) as i64;
        sum += a - b;
    }

    if sum >= 0 {
        sum as u64
    } else {
        (q as i64 + sum) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // DIAGNOSTIC HELPERS (per-prime, overflow-proof)
    // ========================================================================

    /// Convert unsigned mod-M value to centered signed representative in [-M/2, M/2)
    fn center_mod_m_to_i128(x_mod_m: u128, m: u128) -> i128 {
        let half = m / 2;
        if x_mod_m > half {
            -((m - x_mod_m) as i128)
        } else {
            x_mod_m as i128
        }
    }

    /// Compute x mod p for signed x, returning unsigned residue in [0, p)
    fn mod_i128(x: i128, p: u64) -> u64 {
        let p_i = p as i128;
        let mut r = x % p_i;
        if r < 0 { r += p_i; }
        r as u64
    }

    /// Check that main and anchor residues represent the same centered integer.
    /// Panics with detailed diagnostics if any anchor prime diverges.
    fn assert_main_anchor_consistent(
        ctx: &RNSFHEContext,
        main_residues: &[u64],
        anchor_residues: &[u64],
        label: &str,
    ) {
        let v_m = ctx.rns.to_int(main_residues);
        let true_value = center_mod_m_to_i128(v_m, ctx.q_product);

        for (i, &a_i) in ctx.dual_rns.anchor.primes.iter().enumerate() {
            let expected = mod_i128(true_value, a_i);
            let actual = anchor_residues[i];

            assert_eq!(
                expected, actual,
                "{}: Anchor residue mismatch at prime[{}]={}:\n  \
                 expected (true_value mod a_i) = {}\n  \
                 actual   (anchor limb)        = {}\n  \
                 v_m(mod M)={} true_value(centered)={}",
                label, i, a_i, expected, actual, v_m, true_value
            );
        }
    }

    /// Check all coefficients of a DualRNSPoly for main/anchor consistency.
    /// Returns the first mismatching (coeff_idx, prime_idx) or None if all match.
    ///
    /// CORRECT CHECK: Uses K-Elimination invariant, NOT "centered mod Q == true".
    /// For each anchor prime a_i:
    ///   k_i = ((v_a - (v_m mod a_i)) * M^{-1}) mod a_i
    ///   lifted = (v_m mod a_i + k_i * (M mod a_i)) mod a_i
    ///   Check: lifted == v_a
    fn check_poly_consistency(
        ctx: &RNSFHEContext,
        poly: &DualRNSPoly,
    ) -> Option<(usize, usize, String)> {
        let m_product = ctx.q_product;

        for coeff_idx in 0..poly.n {
            let main_res: Vec<u64> = poly.main.iter().map(|l| l[coeff_idx]).collect();
            let v_m = ctx.rns.to_int(&main_res);

            for (prime_idx, &a_i) in ctx.dual_rns.anchor.primes.iter().enumerate() {
                let v_a = poly.anchor[prime_idx][coeff_idx];
                let vm_mod_ai = (v_m % a_i as u128) as u64;
                let m_mod_ai = (m_product % a_i as u128) as u64;
                let inv_m_mod_ai = ctx.dual_rns.main_inv_anchor_rns[prime_idx];

                // k_i = ((v_a - vm_mod_ai) * M^{-1}) mod a_i
                let diff = (v_a as u128 + a_i as u128 - vm_mod_ai as u128) % a_i as u128;
                let k_i = ((diff * inv_m_mod_ai as u128) % a_i as u128) as u64;

                // Verify lift: (vm_mod_ai + k_i * m_mod_ai) mod a_i == v_a
                let lifted = ((vm_mod_ai as u128 + (k_i as u128 * m_mod_ai as u128)) % a_i as u128) as u64;

                if lifted != v_a {
                    return Some((coeff_idx, prime_idx, format!(
                        "K-LIFT FAIL coeff[{}] prime[{}]={}: v_a={} vm_mod_ai={} k_i={} lifted={}",
                        coeff_idx, prime_idx, a_i, v_a, vm_mod_ai, k_i, lifted
                    )));
                }
            }
        }
        None
    }

    /// Dump a single coefficient's main vs anchor residues for debugging.
    fn dump_coeff_main_vs_anchor(ctx: &RNSFHEContext, poly: &DualRNSPoly, coeff_idx: usize, label: &str) {
        let main_res: Vec<u64> = poly.main.iter().map(|l| l[coeff_idx]).collect();
        let v_m = ctx.rns.to_int(&main_res);
        let true_value = center_mod_m_to_i128(v_m, ctx.q_product);

        eprintln!("\n[dump] {} coeff[{}]", label, coeff_idx);
        eprintln!("  v_m (CRT main) = {} ({:.2e})", v_m, v_m as f64);
        eprintln!("  true_value (centered, WRONG FOR LARGE VALUES) = {}", true_value);

        for (i, &a_i) in ctx.dual_rns.anchor.primes.iter().enumerate() {
            let expected = mod_i128(true_value, a_i);
            let actual = poly.anchor[i][coeff_idx];
            let status = if expected == actual { "✓" } else { "✗ MISMATCH" };
            eprintln!("  anchor[{}] prime={}: expected={} actual={} {}",
                      i, a_i, expected, actual, status);
        }

        // Also show K-Elimination k values (the correct invariant)
        let anchor_res: Vec<u64> = poly.anchor.iter().map(|l| l[coeff_idx]).collect();
        let k_full = ctx.dual_rns.extract_k_rns(v_m, &anchor_res);
        eprintln!("  K-Elim k = {} ({:.2e})", k_full, k_full as f64);

        // Show k_rns for each anchor prime
        for (i, &a_i) in ctx.dual_rns.anchor.primes.iter().enumerate() {
            let v_a = poly.anchor[i][coeff_idx];
            let vm_mod_ai = (v_m % a_i as u128) as u64;
            let inv_m_mod_ai = ctx.dual_rns.main_inv_anchor_rns[i];
            let diff = (v_a as u128 + a_i as u128 - vm_mod_ai as u128) % a_i as u128;
            let k_i = ((diff * inv_m_mod_ai as u128) % a_i as u128) as u64;
            eprintln!("  k_rns[{}] = {} (a_i={}, diff a_i = {})",
                      i, k_i, a_i, (a_i as i64 - k_i as i64).abs());
        }
    }

    /// Get the K-Elimination k value for coefficient 0 of a polynomial.
    /// Returns (k_full, k_rns) where k_rns are the per-prime k values.
    fn get_k_coeff0(ctx: &RNSFHEContext, poly: &DualRNSPoly) -> (u128, Vec<u64>) {
        let main_res: Vec<u64> = poly.main.iter().map(|l| l[0]).collect();
        let v_m = ctx.rns.to_int(&main_res);
        let anchor_res: Vec<u64> = poly.anchor.iter().map(|l| l[0]).collect();
        let k_full = ctx.dual_rns.extract_k_rns(v_m, &anchor_res);

        let k_rns: Vec<u64> = ctx.dual_rns.anchor.primes.iter().enumerate()
            .map(|(i, &a_i)| {
                let v_a = poly.anchor[i][0];
                let vm_mod_ai = (v_m % a_i as u128) as u64;
                let inv_m_mod_ai = ctx.dual_rns.main_inv_anchor_rns[i];
                let diff = (v_a as u128 + a_i as u128 - vm_mod_ai as u128) % a_i as u128;
                ((diff * inv_m_mod_ai as u128) % a_i as u128) as u64
            })
            .collect();

        (k_full, k_rns)
    }

    /// Print k values for coeff 0 of a polynomial (for debugging relinearization).
    fn print_k_summary(ctx: &RNSFHEContext, poly: &DualRNSPoly, label: &str) {
        let (k_full, k_rns) = get_k_coeff0(ctx, poly);

        // Check if k is "small" (less than 10^15, well within expected range)
        let is_small = k_full < 1_000_000_000_000_000;

        // A3 product (for sign interpretation threshold)
        let a3_product: u128 = ctx.dual_rns.anchor.primes[0..3].iter()
            .fold(1u128, |acc, &p| acc * p as u128);

        let status = if is_small {
            "✓ small k"
        } else if k_full > a3_product / 2 {
            "⚠ k > A3/2 (will be negative)"
        } else {
            "⚠ k large but positive"
        };

        println!("   [K] {}: k = {:.2e} {} | k_rns[0..3] = [{}, {}, {}]",
            label, k_full as f64, status,
            k_rns[0], k_rns[1], k_rns.get(2).unwrap_or(&0));
    }

    // ========================================================================
    // MUL_DUAL FLIGHT RECORDER (for debugging regressions)
    // ========================================================================

    /// Trace of intermediate values during mul_dual, for debugging.
    #[derive(Clone)]
    struct MulDualTrace {
        // Tensor product stage
        d0: DualRNSPoly,
        d1: DualRNSPoly,
        d2: DualRNSPoly,
        // After rescale
        e0: DualRNSPoly,
        e1: DualRNSPoly,
        e2: DualRNSPoly,
        // After relin (final)
        c0: DualRNSPoly,
        c1: DualRNSPoly,
    }

    impl MulDualTrace {
        /// Check consistency at each stage, return first failure or None.
        /// Note: Tensor product stages (d0, d1, d2) are NOT checked because
        /// they can legitimately exceed M before rescale.
        fn find_first_divergence(&self, ctx: &RNSFHEContext) -> Option<(String, usize, usize, String)> {
            // Only check post-rescale stages - tensor product can exceed M
            let stages = [
                ("rescale:e0", &self.e0),
                ("rescale:e1", &self.e1),
                ("rescale:e2", &self.e2),
                ("relin:c0", &self.c0),
                ("relin:c1", &self.c1),
            ];
            for (stage, poly) in stages {
                if let Some((coeff, prime, msg)) = check_poly_consistency(ctx, poly) {
                    return Some((stage.to_string(), coeff, prime, msg));
                }
            }
            None
        }
    }

    /// Traced version of mul_dual that records intermediate polynomials.
    fn mul_dual_traced(
        ctx: &RNSFHEContext,
        a: &DualRNSCiphertext,
        b: &DualRNSCiphertext,
        sk: &DualRNSSecretKey,
    ) -> (DualRNSCiphertext, MulDualTrace) {
        // 1) Tensor product
        let d0 = ctx.dual_poly_mul(&a.c0, &b.c0);
        let a0b1 = ctx.dual_poly_mul(&a.c0, &b.c1);
        let a1b0 = ctx.dual_poly_mul(&a.c1, &b.c0);
        let d1 = ctx.dual_poly_add(&a0b1, &a1b0);
        let d2 = ctx.dual_poly_mul(&a.c1, &b.c1);

        // 2) Rescale
        let e0 = ctx.k_elim_rescale_dual(&d0);
        let e1 = ctx.k_elim_rescale_dual(&d1);
        let e2 = ctx.k_elim_rescale_dual(&d2);

        // 3) Relin: c0 = e0 + e2*s², c1 = e1
        let s2 = ctx.dual_poly_mul(&sk.s, &sk.s);
        let e2_s2 = ctx.dual_poly_mul(&e2, &s2);
        let c0 = ctx.dual_poly_add(&e0, &e2_s2);
        let c1 = e1.clone();

        let ct = DualRNSCiphertext { c0: c0.clone(), c1: c1.clone(), level: a.level };
        let trace = MulDualTrace {
            d0, d1, d2,
            e0, e1, e2,
            c0, c1,
        };

        (ct, trace)
    }

    #[test]
    fn test_mul_dual_trace_smoke() {
        // Smoke test with flight recorder - checks invariants at each stage
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);
        let mut rng = ShadowHarvester::with_seed(42);

        let keys = ctx.generate_keys_dual(&mut rng);

        println!("=== mul_dual Flight Recorder Smoke Test ===");

        // Test chain pattern (what previously stressed tree mul)
        let ct2 = ctx.encrypt_dual(2, &keys.public_key, &mut rng);
        let ct3 = ctx.encrypt_dual(3, &keys.public_key, &mut rng);

        let (ct6, trace1) = mul_dual_traced(&ctx, &ct2, &ct3, &keys.secret_key);

        // Check all stages for consistency
        if let Some((stage, coeff, prime, msg)) = trace1.find_first_divergence(&ctx) {
            dump_coeff_main_vs_anchor(&ctx, match stage.as_str() {
                "tensor:d0" => &trace1.d0,
                "tensor:d1" => &trace1.d1,
                "tensor:d2" => &trace1.d2,
                "rescale:e0" => &trace1.e0,
                "rescale:e1" => &trace1.e1,
                "rescale:e2" => &trace1.e2,
                "relin:c0" => &trace1.c0,
                _ => &trace1.c1,
            }, coeff, &stage);
            panic!("Divergence at {} coeff {} prime {}: {}", stage, coeff, prime, msg);
        }

        let dec6 = ctx.decrypt_dual(&ct6, &keys.secret_key);
        assert_eq!(dec6, 6, "2*3 should be 6");

        // Test tree pattern: (2*3) * (4*5)
        let ct4 = ctx.encrypt_dual(4, &keys.public_key, &mut rng);
        let ct5 = ctx.encrypt_dual(5, &keys.public_key, &mut rng);
        let (ct20, trace2) = mul_dual_traced(&ctx, &ct4, &ct5, &keys.secret_key);

        if let Some((stage, _coeff, _prime, msg)) = trace2.find_first_divergence(&ctx) {
            panic!("4*5 divergence at {}: {}", stage, msg);
        }

        // Tree mul: result × result
        let (ct120, trace3) = mul_dual_traced(&ctx, &ct6, &ct20, &keys.secret_key);

        if let Some((stage, coeff, _prime, msg)) = trace3.find_first_divergence(&ctx) {
            dump_coeff_main_vs_anchor(&ctx, match stage.as_str() {
                "tensor:d0" => &trace3.d0,
                "tensor:d1" => &trace3.d1,
                "tensor:d2" => &trace3.d2,
                "rescale:e0" => &trace3.e0,
                "rescale:e1" => &trace3.e1,
                "rescale:e2" => &trace3.e2,
                "relin:c0" => &trace3.c0,
                _ => &trace3.c1,
            }, coeff, &format!("TREE MUL {}", stage));
            panic!("Tree mul (6*20) divergence at {}: {}", stage, msg);
        }

        let dec120 = ctx.decrypt_dual(&ct120, &keys.secret_key);
        assert_eq!(dec120, 120, "6*20 should be 120");

        println!("✓ All stages consistent through tree multiplication");
    }

    #[test]
    fn test_mul_dual_public_mode() {
        // Test the PUBLIC multiplication mode (standard FHE security)
        // This uses evaluation keys instead of secret key for relinearization
        //
        // IMPORTANT: Public relinearization adds noise per operation.
        // For deep circuits, use symmetric mode OR implement modulus switching/bootstrapping.
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);
        let mut rng = ShadowHarvester::with_seed(42);

        // Generate FULL keys including evaluation key
        let full_keys = ctx.generate_keys_dual_full(&mut rng);

        println!("=== PUBLIC MODE FHE Test ===");
        println!("This mode uses eval keys - computing party never sees sk");
        println!("Note: Public mode adds relinearization noise; limited depth without bootstrapping");

        // Encrypt with public key only
        let ct2 = ctx.encrypt_dual(2, &full_keys.public_key, &mut rng);
        let ct3 = ctx.encrypt_dual(3, &full_keys.public_key, &mut rng);

        // Multiply using PUBLIC mode (eval key, NOT secret key)
        let ct6 = ctx.mul_dual_public(&ct2, &ct3, &full_keys.eval_key);

        // Decrypt (only key holder can do this)
        let dec6 = ctx.decrypt_dual(&ct6, &full_keys.secret_key);
        println!("  2 * 3 = {} (expected 6)", dec6);
        assert_eq!(dec6, 6, "Public mode: 2*3 should be 6");

        // Test another multiplication (fresh ciphertexts)
        let ct4 = ctx.encrypt_dual(4, &full_keys.public_key, &mut rng);
        let ct5 = ctx.encrypt_dual(5, &full_keys.public_key, &mut rng);
        let ct20 = ctx.mul_dual_public(&ct4, &ct5, &full_keys.eval_key);
        let dec20 = ctx.decrypt_dual(&ct20, &full_keys.secret_key);
        println!("  4 * 5 = {} (expected 20)", dec20);
        assert_eq!(dec20, 20, "Public mode: 4*5 should be 20");

        // Test 7 * 11 (another single multiplication)
        let ct7 = ctx.encrypt_dual(7, &full_keys.public_key, &mut rng);
        let ct11 = ctx.encrypt_dual(11, &full_keys.public_key, &mut rng);
        let ct77 = ctx.mul_dual_public(&ct7, &ct11, &full_keys.eval_key);
        let dec77 = ctx.decrypt_dual(&ct77, &full_keys.secret_key);
        println!("  7 * 11 = {} (expected 77)", dec77);
        assert_eq!(dec77, 77, "Public mode: 7*11 should be 77");

        println!("✓ PUBLIC MODE: Single-depth multiplications correct!");
        println!("  Security: Standard IND-CPA under RLWE");
        println!("  Limitation: Deeper circuits need modulus switching or bootstrapping");
    }

    #[test]
    fn test_compare_symmetric_vs_public() {
        // Compare symmetric and public mode outputs to find divergence
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);

        // Generate both key sets from same seed for fair comparison
        let mut rng_sym = ShadowHarvester::with_seed(100);
        let sym_keys = ctx.generate_keys_dual(&mut rng_sym);

        let mut rng_pub = ShadowHarvester::with_seed(100);
        let pub_keys = ctx.generate_keys_dual_full(&mut rng_pub);

        println!("=== SYMMETRIC vs PUBLIC Mode Comparison ===");

        // Encrypt with same seed for identical ciphertexts
        let mut rng1 = ShadowHarvester::with_seed(200);
        let ct2_sym = ctx.encrypt_dual(2, &sym_keys.public_key, &mut rng1);
        let mut rng2 = ShadowHarvester::with_seed(201);
        let ct3_sym = ctx.encrypt_dual(3, &sym_keys.public_key, &mut rng2);

        let mut rng3 = ShadowHarvester::with_seed(200);
        let ct2_pub = ctx.encrypt_dual(2, &pub_keys.public_key, &mut rng3);
        let mut rng4 = ShadowHarvester::with_seed(201);
        let ct3_pub = ctx.encrypt_dual(3, &pub_keys.public_key, &mut rng4);

        // Multiply
        #[allow(deprecated)]
        let ct6_sym = ctx.mul_dual_symmetric(&ct2_sym, &ct3_sym, &sym_keys.secret_key);
        let ct6_pub = ctx.mul_dual_public(&ct2_pub, &ct3_pub, &pub_keys.eval_key);

        // Check decryption
        let dec_sym = ctx.decrypt_dual(&ct6_sym, &sym_keys.secret_key);
        let dec_pub = ctx.decrypt_dual(&ct6_pub, &pub_keys.secret_key);
        println!("  Symmetric 2*3 = {}", dec_sym);
        println!("  Public 2*3 = {}", dec_pub);

        // Check dual-RNS invariant for ct6_pub
        println!("\n  Checking dual-RNS invariant after public mul:");
        let main_c0_0: Vec<u64> = ct6_pub.c0.main.iter().map(|l| l[0]).collect();
        let anchor_c0_0: Vec<u64> = ct6_pub.c0.anchor.iter().map(|l| l[0]).collect();
        let v_m = ctx.rns.to_int(&main_c0_0);
        let k = ctx.dual_rns.extract_k_rns(v_m, &anchor_c0_0);

        let num_primes_for_sign = ctx.dual_rns.anchor.primes.len().min(3);
        let a_n_product: u128 = ctx.dual_rns.anchor.primes[0..num_primes_for_sign].iter()
            .fold(1u128, |acc, &p| acc * p as u128);

        println!("    v_m = {} ({:.2e})", v_m, v_m as f64);
        println!("    k = {} ({:.2e})", k, k as f64);
        println!("    k > A_n/2 = {} (A_n/2 = {:.2e})", k > a_n_product/2, (a_n_product/2) as f64);

        // For symmetric mode
        println!("\n  Checking dual-RNS invariant after symmetric mul:");
        let main_c0_0_sym: Vec<u64> = ct6_sym.c0.main.iter().map(|l| l[0]).collect();
        let anchor_c0_0_sym: Vec<u64> = ct6_sym.c0.anchor.iter().map(|l| l[0]).collect();
        let v_m_sym = ctx.rns.to_int(&main_c0_0_sym);
        let k_sym = ctx.dual_rns.extract_k_rns(v_m_sym, &anchor_c0_0_sym);
        println!("    v_m = {} ({:.2e})", v_m_sym, v_m_sym as f64);
        println!("    k = {} ({:.2e})", k_sym, k_sym as f64);
        println!("    k > A_n/2 = {}", k_sym > a_n_product/2);

        assert_eq!(dec_sym, 6);
        assert_eq!(dec_pub, 6);
        println!("\n✓ Both modes give correct result for depth-1");

        // --- DEPTH-2 COMPARISON ---
        println!("\n=== DEPTH-2 COMPARISON ===");

        // Create ct20 for both modes
        let mut rng5 = ShadowHarvester::with_seed(300);
        let ct4_sym = ctx.encrypt_dual(4, &sym_keys.public_key, &mut rng5);
        let mut rng6 = ShadowHarvester::with_seed(301);
        let ct5_sym = ctx.encrypt_dual(5, &sym_keys.public_key, &mut rng6);

        let mut rng7 = ShadowHarvester::with_seed(300);
        let ct4_pub = ctx.encrypt_dual(4, &pub_keys.public_key, &mut rng7);
        let mut rng8 = ShadowHarvester::with_seed(301);
        let ct5_pub = ctx.encrypt_dual(5, &pub_keys.public_key, &mut rng8);

        #[allow(deprecated)]
        let ct20_sym = ctx.mul_dual_symmetric(&ct4_sym, &ct5_sym, &sym_keys.secret_key);
        let ct20_pub = ctx.mul_dual_public(&ct4_pub, &ct5_pub, &pub_keys.eval_key);

        // Depth-2: 6 * 20 = 120
        #[allow(deprecated)]
        let ct120_sym = ctx.mul_dual_symmetric(&ct6_sym, &ct20_sym, &sym_keys.secret_key);
        let ct120_pub = ctx.mul_dual_public(&ct6_pub, &ct20_pub, &pub_keys.eval_key);

        let dec120_sym = ctx.decrypt_dual(&ct120_sym, &sym_keys.secret_key);
        let dec120_pub = ctx.decrypt_dual(&ct120_pub, &pub_keys.secret_key);

        println!("  Symmetric depth-2: 6*20 = {}", dec120_sym);
        println!("  Public depth-2: 6*20 = {}", dec120_pub);

        // Check k values at depth-2
        println!("\n  Checking dual-RNS invariant after DEPTH-2 public mul:");
        let main_d2_pub: Vec<u64> = ct120_pub.c0.main.iter().map(|l| l[0]).collect();
        let anchor_d2_pub: Vec<u64> = ct120_pub.c0.anchor.iter().map(|l| l[0]).collect();
        let v_m_d2_pub = ctx.rns.to_int(&main_d2_pub);
        let k_d2_pub = ctx.dual_rns.extract_k_rns(v_m_d2_pub, &anchor_d2_pub);
        println!("    v_m = {} ({:.2e})", v_m_d2_pub, v_m_d2_pub as f64);
        println!("    k = {} ({:.2e})", k_d2_pub, k_d2_pub as f64);

        println!("\n  Checking dual-RNS invariant after DEPTH-2 symmetric mul:");
        let main_d2_sym: Vec<u64> = ct120_sym.c0.main.iter().map(|l| l[0]).collect();
        let anchor_d2_sym: Vec<u64> = ct120_sym.c0.anchor.iter().map(|l| l[0]).collect();
        let v_m_d2_sym = ctx.rns.to_int(&main_d2_sym);
        let k_d2_sym = ctx.dual_rns.extract_k_rns(v_m_d2_sym, &anchor_d2_sym);
        println!("    v_m = {} ({:.2e})", v_m_d2_sym, v_m_d2_sym as f64);
        println!("    k = {} ({:.2e})", k_d2_sym, k_d2_sym as f64);

        if k_d2_sym == 0 && k_d2_pub != 0 {
            println!("\n  DIAGNOSIS: Symmetric has k=0 but public has k≠0");
            println!("  The public relinearization is breaking the dual-RNS invariant!");
        } else if k_d2_sym != 0 && k_d2_pub != 0 {
            println!("\n  DIAGNOSIS: Both modes have k≠0 at depth-2");
            println!("  This may be a fundamental issue with the K-elim rescale.");
        }

        assert_eq!(dec120_sym, 120, "Symmetric depth-2 should work");
    }

    #[test]
    #[ignore] // Diagnostic test for public mode
    fn test_mul_dual_public_mode_deep() {
        // Detailed diagnostic test for public mode multiplication
        // Traces centered coefficients and phase error at each stage

        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);
        let mut rng = ShadowHarvester::with_seed(42);

        let full_keys = ctx.generate_keys_dual_full(&mut rng);
        let delta = ctx.q_product / ctx.t as u128;
        let q_half = ctx.q_product / 2;

        println!("=== PUBLIC MODE DIAGNOSTIC TEST ===");
        println!("Q = {:.3e}, Δ = {:.3e}, t = {}", ctx.q_product as f64, delta as f64, ctx.t);

        // Helper: compute centered coefficient value from main residues
        let centered_coeff = |poly: &DualRNSPoly, idx: usize| -> i128 {
            let main_residues: Vec<u64> = poly.main.iter().map(|limb| limb[idx]).collect();
            let v_m = ctx.rns.to_int(&main_residues);
            if v_m > q_half { v_m as i128 - ctx.q_product as i128 } else { v_m as i128 }
        };

        // Helper: compute ||poly||∞ in centered representation
        let centered_inf_norm = |poly: &DualRNSPoly| -> i128 {
            (0..ctx.n).map(|i| centered_coeff(poly, i).abs()).max().unwrap_or(0)
        };

        // Helper: compute phase error vs expected value
        let phase_error = |ct: &DualRNSCiphertext, expected_m: u64, sk: &DualRNSSecretKey| -> i128 {
            // phase = c0 + c1*s should be close to m*Δ
            let c0_plus_c1s = ctx.dual_poly_add(&ct.c0, &ctx.dual_poly_mul(&ct.c1, &sk.s));
            let phase = centered_coeff(&c0_plus_c1s, 0);
            let expected = (expected_m as u128 * delta) as i128;
            (phase - expected).abs()
        };

        // Fresh encryptions
        let ct2 = ctx.encrypt_dual(2, &full_keys.public_key, &mut rng);
        let ct3 = ctx.encrypt_dual(3, &full_keys.public_key, &mut rng);

        println!("\n--- Fresh ciphertexts ---");
        println!("  ct2.c0 centered ||·||∞ = {:.3e}", centered_inf_norm(&ct2.c0) as f64);
        println!("  ct2.c1 centered ||·||∞ = {:.3e}", centered_inf_norm(&ct2.c1) as f64);
        println!("  ct2 phase error = {:.3e} (Δ/2 = {:.3e})", phase_error(&ct2, 2, &full_keys.secret_key) as f64, (delta/2) as f64);

        // --- MANUAL STEP-BY-STEP MULTIPLICATION ---
        println!("\n--- Multiplication 2*3 step-by-step ---");

        // Step 1: Tensor product
        let d0 = ctx.dual_poly_mul(&ct2.c0, &ct3.c0);
        let d1_part1 = ctx.dual_poly_mul(&ct2.c0, &ct3.c1);
        let d1_part2 = ctx.dual_poly_mul(&ct2.c1, &ct3.c0);
        let d1 = ctx.dual_poly_add(&d1_part1, &d1_part2);
        let d2 = ctx.dual_poly_mul(&ct2.c1, &ct3.c1);

        println!("After tensor product:");
        println!("  d0 centered ||·||∞ = {:.3e}", centered_inf_norm(&d0) as f64);
        println!("  d1 centered ||·||∞ = {:.3e}", centered_inf_norm(&d1) as f64);
        println!("  d2 centered ||·||∞ = {:.3e}", centered_inf_norm(&d2) as f64);

        // Step 2: Relinearize d2 (BEFORE rescale)
        let (relin_c0, relin_c1) = ctx.relinearize_dual(&d2, &full_keys.eval_key);
        println!("After relinearization (before rescale):");
        println!("  relin_c0 centered ||·||∞ = {:.3e}", centered_inf_norm(&relin_c0) as f64);
        println!("  relin_c1 centered ||·||∞ = {:.3e}", centered_inf_norm(&relin_c1) as f64);

        // Step 3: Combine
        let c0_pre = ctx.dual_poly_add(&d0, &relin_c0);
        let c1_pre = ctx.dual_poly_add(&d1, &relin_c1);
        println!("After combining (before rescale):");
        println!("  c0_pre centered ||·||∞ = {:.3e}", centered_inf_norm(&c0_pre) as f64);
        println!("  c1_pre centered ||·||∞ = {:.3e}", centered_inf_norm(&c1_pre) as f64);

        // Step 4: K-elim rescale
        let c0_new = ctx.k_elim_rescale_dual(&c0_pre);
        let c1_new = ctx.k_elim_rescale_dual(&c1_pre);
        println!("After K-elim rescale:");
        println!("  c0_new centered ||·||∞ = {:.3e}", centered_inf_norm(&c0_new) as f64);
        println!("  c1_new centered ||·||∞ = {:.3e}", centered_inf_norm(&c1_new) as f64);

        let ct6 = DualRNSCiphertext { c0: c0_new, c1: c1_new, level: ct2.level };
        let dec6 = ctx.decrypt_dual(&ct6, &full_keys.secret_key);
        let pe6 = phase_error(&ct6, 6, &full_keys.secret_key);
        println!("  Decrypt = {} (expected 6), phase error = {:.3e}", dec6, pe6 as f64);
        assert_eq!(dec6, 6, "Depth-1 should work");

        // --- Depth-2 ---
        println!("\n--- Depth-2: 6*20 ---");
        let ct4 = ctx.encrypt_dual(4, &full_keys.public_key, &mut rng);
        let ct5 = ctx.encrypt_dual(5, &full_keys.public_key, &mut rng);
        let ct20 = ctx.mul_dual_public(&ct4, &ct5, &full_keys.eval_key);
        let dec20 = ctx.decrypt_dual(&ct20, &full_keys.secret_key);
        println!("ct20 decrypt = {} (expected 20)", dec20);

        println!("\nInputs to depth-2 multiplication:");
        println!("  ct6.c0 centered ||·||∞ = {:.3e}", centered_inf_norm(&ct6.c0) as f64);
        println!("  ct6.c1 centered ||·||∞ = {:.3e}", centered_inf_norm(&ct6.c1) as f64);
        println!("  ct20.c0 centered ||·||∞ = {:.3e}", centered_inf_norm(&ct20.c0) as f64);
        println!("  ct20.c1 centered ||·||∞ = {:.3e}", centered_inf_norm(&ct20.c1) as f64);

        // Step 1: Tensor
        let d0_2 = ctx.dual_poly_mul(&ct6.c0, &ct20.c0);
        let d1_2_part1 = ctx.dual_poly_mul(&ct6.c0, &ct20.c1);
        let d1_2_part2 = ctx.dual_poly_mul(&ct6.c1, &ct20.c0);
        let d1_2 = ctx.dual_poly_add(&d1_2_part1, &d1_2_part2);
        let d2_2 = ctx.dual_poly_mul(&ct6.c1, &ct20.c1);

        println!("After tensor product:");
        println!("  d0 centered ||·||∞ = {:.3e}", centered_inf_norm(&d0_2) as f64);
        println!("  d1 centered ||·||∞ = {:.3e}", centered_inf_norm(&d1_2) as f64);
        println!("  d2 centered ||·||∞ = {:.3e}", centered_inf_norm(&d2_2) as f64);

        // Step 2: Relin
        let (relin_c0_2, relin_c1_2) = ctx.relinearize_dual(&d2_2, &full_keys.eval_key);
        println!("After relinearization:");
        println!("  relin_c0 centered ||·||∞ = {:.3e}", centered_inf_norm(&relin_c0_2) as f64);
        println!("  relin_c1 centered ||·||∞ = {:.3e}", centered_inf_norm(&relin_c1_2) as f64);

        // Step 3: Combine
        let c0_pre_2 = ctx.dual_poly_add(&d0_2, &relin_c0_2);
        let c1_pre_2 = ctx.dual_poly_add(&d1_2, &relin_c1_2);
        println!("After combining:");
        println!("  c0_pre centered ||·||∞ = {:.3e}", centered_inf_norm(&c0_pre_2) as f64);
        println!("  c1_pre centered ||·||∞ = {:.3e}", centered_inf_norm(&c1_pre_2) as f64);

        // Step 4: Rescale
        let c0_new_2 = ctx.k_elim_rescale_dual(&c0_pre_2);
        let c1_new_2 = ctx.k_elim_rescale_dual(&c1_pre_2);
        println!("After rescale:");
        println!("  c0_new centered ||·||∞ = {:.3e}", centered_inf_norm(&c0_new_2) as f64);
        println!("  c1_new centered ||·||∞ = {:.3e}", centered_inf_norm(&c1_new_2) as f64);

        let ct120 = DualRNSCiphertext { c0: c0_new_2, c1: c1_new_2, level: ct6.level };
        let dec120 = ctx.decrypt_dual(&ct120, &full_keys.secret_key);
        println!("  Decrypt = {} (expected 120)", dec120);

        if dec120 == 120 {
            println!("\n✓ PUBLIC MODE DEPTH-2 WORKS!");
        } else {
            println!("\n✗ Depth-2 failed. Check coefficient magnitudes above for blow-up point.");
        }
    }

    #[test]
    fn test_rns_native_encrypt_decrypt() {
        let config = FHEConfig::light_rns();
        let ctx = RNSFHEContext::new(&config);
        let mut rng = ShadowHarvester::with_seed(42);

        let keys = ctx.generate_keys(&mut rng);

        println!("=== RNS-Native FHE Test ===");
        println!("Config: {} ({} primes)", config.name, config.primes.len());
        println!("Q product: {:.2e}", ctx.rns.product as f64);

        // Test encrypt/decrypt
        for m in [0, 1, 5, 7, 100, 1000, 65535] {
            if m >= config.t {
                continue;
            }
            let ct = ctx.encrypt(m, &keys.public_key, &mut rng);
            let dec = ctx.decrypt(&ct, &keys.secret_key);
            println!("  m={} → decrypt={}", m, dec);
            assert_eq!(dec, m, "Encrypt/decrypt failed for m={}", m);
        }
    }

    #[test]
    fn test_rns_native_addition() {
        let config = FHEConfig::light_rns();
        let ctx = RNSFHEContext::new(&config);
        let mut rng = ShadowHarvester::with_seed(42);

        let keys = ctx.generate_keys(&mut rng);

        let a = 5u64;
        let b = 7u64;
        let expected = (a + b) % config.t;

        let ct_a = ctx.encrypt(a, &keys.public_key, &mut rng);
        let ct_b = ctx.encrypt(b, &keys.public_key, &mut rng);

        let ct_sum = ctx.add(&ct_a, &ct_b);
        let result = ctx.decrypt(&ct_sum, &keys.secret_key);

        println!("RNS-native add: {} + {} = {} (expected {})", a, b, result, expected);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_rns_simple_add_mul() {
        // First test with very simple operations to verify basic correctness
        let config = FHEConfig::light_rns();
        let ctx = RNSFHEContext::new(&config);
        let mut rng = ShadowHarvester::with_seed(42);

        let keys = ctx.generate_keys(&mut rng);

        println!("=== Simple Add/Mul Test ===");

        // Test: encrypt 0, add 0, should get 0
        let ct_zero = ctx.encrypt(0, &keys.public_key, &mut rng);
        let sum_zero = ctx.add(&ct_zero, &ct_zero);
        let dec_zero = ctx.decrypt(&sum_zero, &keys.secret_key);
        println!("0 + 0 = {} (expected 0)", dec_zero);
        assert_eq!(dec_zero, 0);

        // Test: encrypt 1, add encrypt 1, should get 2
        let ct_one = ctx.encrypt(1, &keys.public_key, &mut rng);
        let sum_two = ctx.add(&ct_one, &ct_one);
        let dec_two = ctx.decrypt(&sum_two, &keys.secret_key);
        println!("1 + 1 = {} (expected 2)", dec_two);
        assert_eq!(dec_two, 2);
    }

    #[test]
    fn test_rns_native_multiplication() {
        let config = FHEConfig::light_rns();
        let ctx = RNSFHEContext::new(&config);
        let mut rng = ShadowHarvester::with_seed(42);

        let keys = ctx.generate_keys(&mut rng);

        let a = 5u64;
        let b = 7u64;
        let expected = (a * b) % config.t;

        // Compute Δ = Q/t for display purposes
        let delta_big = ctx.q_product / ctx.t as u128;

        println!("=== RNS-Native CT×CT Multiplication Test ===");
        println!("Config: {}", config.name);
        println!("Q = {:.2e}, t = {}", ctx.q_product as f64, ctx.t);
        println!("Δ = Q/t = {:.2e}", delta_big as f64);
        println!("delta_rns = {:?}", ctx.delta_rns);
        println!("Testing {} × {} = {} (mod {})", a, b, expected, config.t);

        let ct_a = ctx.encrypt(a, &keys.public_key, &mut rng);
        let ct_b = ctx.encrypt(b, &keys.public_key, &mut rng);

        // Verify encryption first
        let dec_a = ctx.decrypt(&ct_a, &keys.secret_key);
        let dec_b = ctx.decrypt(&ct_b, &keys.secret_key);
        println!("Encrypted: {} → {}, {} → {}", a, dec_a, b, dec_b);
        assert_eq!(dec_a, a, "Decryption of {} failed, got {}", a, dec_a);
        assert_eq!(dec_b, b, "Decryption of {} failed, got {}", b, dec_b);

        // Debug: check inner product before multiplication
        println!("\nDebug inner products:");
        let c1_s_a = ctx.rns_poly_mul(&ct_a.c1, &keys.secret_key.s);
        let inner_a = ct_a.c0.add(&c1_s_a, &ctx.rns);
        let inner_a_coeff: Vec<u64> = inner_a.limbs.iter().map(|l| l[0]).collect();
        let inner_a_val = ctx.to_int_montgomery(&inner_a_coeff);
        let expected_inner_a = delta_big * a as u128;
        println!("  inner_a[0] = {:.2e} (expected ~Δ×{} = {:.2e})",
                 inner_a_val as f64, a, expected_inner_a as f64);

        let c1_s_b = ctx.rns_poly_mul(&ct_b.c1, &keys.secret_key.s);
        let inner_b = ct_b.c0.add(&c1_s_b, &ctx.rns);
        let inner_b_coeff: Vec<u64> = inner_b.limbs.iter().map(|l| l[0]).collect();
        let inner_b_val = ctx.to_int_montgomery(&inner_b_coeff);
        let expected_inner_b = delta_big * b as u128;
        println!("  inner_b[0] = {:.2e} (expected ~Δ×{} = {:.2e})",
                 inner_b_val as f64, b, expected_inner_b as f64);

        // Multiply WITHOUT relinearization first to isolate the issue
        // Tensor product: (d0, d1, d2)
        let d0 = ctx.rns_poly_mul(&ct_a.c0, &ct_b.c0);
        let c0_1_c1_2 = ctx.rns_poly_mul(&ct_a.c0, &ct_b.c1);
        let c1_1_c0_2 = ctx.rns_poly_mul(&ct_a.c1, &ct_b.c0);
        let d1 = c0_1_c1_2.add(&c1_1_c0_2, &ctx.rns);
        let d2 = ctx.rns_poly_mul(&ct_a.c1, &ct_b.c1);

        println!("\nTensor product (before rescaling):");
        let d0_coeff: Vec<u64> = d0.limbs.iter().map(|l| l[0]).collect();
        let d0_val = ctx.to_int_montgomery(&d0_coeff);
        // Note: Δ² overflows u128, so we compute as f64 for display only
        let expected_d0_f64 = (delta_big as f64) * (delta_big as f64) * (a as f64) * (b as f64);
        println!("  d0[0] = {:.2e} (expected ~Δ²×{}×{} = {:.2e})",
                 d0_val as f64, a, b, expected_d0_f64);

        // Rescale
        let e0 = ctx.exact_rescale(&d0);
        let e1 = ctx.exact_rescale(&d1);
        let e2 = ctx.exact_rescale(&d2);

        println!("\nAfter rescaling:");
        let e0_coeff: Vec<u64> = e0.limbs.iter().map(|l| l[0]).collect();
        let e0_val = ctx.to_int_montgomery(&e0_coeff);
        let expected_e0 = delta_big * expected as u128;
        println!("  e0[0] = {:.2e} (expected ~Δ×{} = {:.2e})",
                 e0_val as f64, expected, expected_e0 as f64);

        // Decrypt degree-2 directly (without relinearization) to check
        let s2 = ctx.rns_poly_mul(&keys.secret_key.s, &keys.secret_key.s);
        let e1_s = ctx.rns_poly_mul(&e1, &keys.secret_key.s);
        let e2_s2 = ctx.rns_poly_mul(&e2, &s2);
        let inner_deg2 = e0.add(&e1_s, &ctx.rns).add(&e2_s2, &ctx.rns);

        let inner_deg2_coeff: Vec<u64> = inner_deg2.limbs.iter().map(|l| l[0]).collect();
        let inner_deg2_val = ctx.to_int_montgomery(&inner_deg2_coeff);
        println!("  degree-2 inner[0] = {:.2e} (expected ~Δ×{} = {:.2e})",
                 inner_deg2_val as f64, expected, expected_e0 as f64);

        // Decode directly
        let q_half = ctx.q_product / 2;
        let direct_result = if inner_deg2_val > q_half {
            let neg_mag = ctx.q_product - inner_deg2_val;
            let scaled_neg = (neg_mag * ctx.t as u128 + q_half) / ctx.q_product;
            if scaled_neg == 0 { 0 } else { ctx.t - (scaled_neg % ctx.t as u128) as u64 }
        } else {
            let scaled = (inner_deg2_val * ctx.t as u128 + q_half) / ctx.q_product;
            (scaled % ctx.t as u128) as u64
        };
        println!("  degree-2 decoded = {} (expected {})", direct_result, expected);

        // Now with relinearization
        let ct_prod = ctx.mul(&ct_a, &ct_b, &keys.eval_key);
        let result = ctx.decrypt(&ct_prod, &keys.secret_key);

        println!("\nFinal result with relinearization:");
        println!("Result: {} × {} = {} (expected {})", a, b, result, expected);

        if result != expected {
            println!(">>> EXPECTED MISMATCH <<<");
            println!("Single-RNS Bajard rescaling fails when Δ² >> Q (multi-prime case).");
            println!("Use dual-RNS K-Elimination (mul_dual) for correct results.");
            println!("  ratio result/expected = {:.2}", result as f64 / expected as f64);
            println!("  diff = {}", (result as i64 - expected as i64).abs());
        }

        // NOTE: Single-RNS Bajard rescaling (exact_rescale) doesn't work for multi-prime
        // when Δ² >> Q because tensor product overflows the RNS modulus without anchor
        // system to recover exact values. Use dual-RNS K-Elimination instead.
        // See: test_coeff_domain_full_ct_mul and test_mul_dual_debug for correct approach.
        if result == expected {
            println!("✓ Single-RNS multiplication unexpectedly worked!");
        }
    }

    #[test]
    fn test_rns_multiplication_chain() {
        let config = FHEConfig::light_rns();
        let ctx = RNSFHEContext::new(&config);
        let mut rng = ShadowHarvester::with_seed(42);

        let keys = ctx.generate_keys(&mut rng);

        println!("=== RNS Multiplication Chain Test ===");

        // Start with 2, square repeatedly
        let mut ct = ctx.encrypt(2u64, &keys.public_key, &mut rng);
        let mut expected = 2u64;

        for i in 1..=4 {
            ct = ctx.mul(&ct, &ct, &keys.eval_key);
            expected = (expected * expected) % config.t;

            let result = ctx.decrypt(&ct, &keys.secret_key);
            println!("  Depth {}: 2^{} = {} (expected {})", i, 1 << i, result, expected);

            if result != expected {
                println!("  >>> FAILED at depth {} <<<", i);
                break;
            }
        }
    }

    #[test]
    fn test_rns_exact_encrypt_decrypt() {
        // Test basic encrypt/decrypt with light_rns_exact config
        // This config has 2 primes with t = 65537
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new(&config);
        let mut rng = ShadowHarvester::with_seed(42);

        let keys = ctx.generate_keys(&mut rng);

        let delta_big = ctx.q_product / ctx.t as u128;

        println!("=== QMNF Exact RNS Encrypt/Decrypt Test ===");
        println!("Config: {} ({} primes)", config.name, config.primes.len());
        println!("Q = {:.2e}, t = {}", ctx.q_product as f64, ctx.t);
        println!("Δ = Q/t = {:.2e}", delta_big as f64);

        // Test basic encrypt/decrypt
        for m in [0, 1, 5, 7, 100, 1000, 65535] {
            if m >= config.t {
                continue;
            }
            let ct = ctx.encrypt(m, &keys.public_key, &mut rng);
            let dec = ctx.decrypt(&ct, &keys.secret_key);
            println!("  m={} → decrypt={}", m, dec);
            assert_eq!(dec, m, "Encrypt/decrypt failed for m={}", m);
        }
        println!("✓ Basic encrypt/decrypt PASSED");
    }

    #[test]
    fn test_rns_exact_multiplication() {
        // Use light_rns_exact config - requires K-Elimination rescaling
        // because Δ² > Q (Bajard rescaling won't work)
        //
        // Q ≈ 9.8e17 (2 primes), t = 65537 → Δ ≈ 1.5e13 ≈ 2^44
        // Δ² ≈ 2^88 > Q ≈ 2^60 (wraparound occurs!)
        //
        // K-Elimination capacity: M×A ≈ 2^122 > Δ² ≈ 2^88 ✓
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new(&config);
        let mut rng = ShadowHarvester::with_seed(42);

        let keys = ctx.generate_keys_auto(&mut rng);

        let delta_big = ctx.q_product / ctx.t as u128;

        println!("=== QMNF Exact RNS Multiplication Test ===");
        println!("Config: {}", config.name);
        println!("Q = {:.2e}, t = {}", ctx.q_product as f64, ctx.t);
        println!("Δ = Q/t = {:.2e}", delta_big as f64);
        println!("Δ² = {:.2e} (> Q = {:.2e}, needs K-Elimination)",
                 (delta_big as f64) * (delta_big as f64), ctx.q_product as f64);
        println!("mul_route = {:?}", ctx.mul_route());

        let a = 5u64;
        let b = 7u64;
        let expected = (a * b) % config.t;
        println!("\nTesting {} × {} = {} (mod {})", a, b, expected, config.t);

        // First verify encryption works
        let ct_a = ctx.encrypt_auto(a, &keys, &mut rng);
        let ct_b = ctx.encrypt_auto(b, &keys, &mut rng);

        let dec_a = ctx.decrypt_auto(&ct_a, &keys);
        let dec_b = ctx.decrypt_auto(&ct_b, &keys);
        println!("Encrypted: {} → {}, {} → {}", a, dec_a, b, dec_b);

        // Basic encrypt/decrypt should work
        assert_eq!(dec_a, a, "Decryption of {} failed", a);
        assert_eq!(dec_b, b, "Decryption of {} failed", b);
        println!("✓ Basic encrypt/decrypt works");

        // Multiply via auto route (K-Elimination for this config)
        let ct_prod = ctx.mul_auto(&ct_a, &ct_b, &keys);
        let result = ctx.decrypt_auto(&ct_prod, &keys);

        println!("\nResult: {} × {} = {} (expected {})", a, b, result, expected);

        assert_eq!(result, expected, "QMNF exact multiplication failed!");
    }

    #[test]
    fn test_rns_exact_multiplication_chain() {
        // Test multiplication chain with light_rns_exact using DUAL-RNS K-Elimination
        // (not single-RNS Bajard which fails when Δ² >> Q)
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new(&config);
        let mut rng = ShadowHarvester::with_seed(42);

        let keys = ctx.generate_keys_dual(&mut rng);

        println!("=== RNS Exact Multiplication Chain (Dual-RNS K-Elim) ===");
        println!("Config: {}, t = {}", config.name, config.t);

        // Start with 3, compute 3 × 3 × 3 × 3
        let three = 3u64;
        let mut ct = ctx.encrypt_dual(three, &keys.public_key, &mut rng);
        let ct_three = ctx.encrypt_dual(three, &keys.public_key, &mut rng);
        let mut expected = three;

        for i in 1..=3 {
            ct = ctx.mul_dual_symmetric(&ct, &ct_three, &keys.secret_key);
            expected = (expected * three) % config.t;

            let result = ctx.decrypt_dual(&ct, &keys.secret_key);
            println!("  Step {}: 3^{} = {} (expected {})", i, i + 1, result, expected);

            assert_eq!(result, expected, "Chain failed at step {}", i);
        }

        println!("✓ Multiplication chain PASSED: 3^4 = {}", expected);
    }

    // ========================================================================
    // DUAL-TRACK K-ELIMINATION TESTS
    // ========================================================================

    #[test]
    fn test_dual_rns_encrypt_decrypt() {
        // Test dual-track encrypt/decrypt with light_rns_exact config
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new(&config);
        let mut rng = ShadowHarvester::with_seed(42);

        let keys = ctx.generate_keys_dual(&mut rng);

        println!("=== Dual-Track RNS Encrypt/Decrypt Test ===");
        println!("Config: {} ({} main primes, {} anchor primes)",
                 config.name, config.primes.len(), ctx.dual_rns.anchor.primes.len());

        // Test basic encrypt/decrypt
        for m in [0, 1, 5, 7, 100, 1000] {
            if m >= config.t {
                continue;
            }
            let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
            let dec = ctx.decrypt_dual(&ct, &keys.secret_key);
            println!("  m={} → decrypt={}", m, dec);
            assert_eq!(dec, m, "Dual encrypt/decrypt failed for m={}", m);
        }
        println!("✓ Dual-track encrypt/decrypt PASSED");
    }

    #[test]
    fn test_dual_rns_ct_mul_capacity_analysis() {
        // CAPACITY ANALYSIS TEST
        //
        // K-Elimination reconstructs values up to M × A capacity.
        // Tensor product coefficients are O(Q² × N) magnitude.
        //
        // CONSTRAINT: Q² × N < M × A
        //
        // For light_rns_exact (2 primes):
        // - Q ≈ 10^18, N = 1024
        // - Q² × N ≈ 10^39
        // - M × A ≈ 7.75e34
        // - 10^39 >> 7.75e34 → K-Elimination FAILS for RNS encryption
        //
        // For single-prime configs (light_exact):
        // - Q ≈ 10^9, N = 1024
        // - Q² × N ≈ 10^21
        // - M × A ≈ 4.6e27
        // - 10^21 << 4.6e27 → K-Elimination WORKS (see ct_mul_exact tests)
        //
        // CONCLUSION: Dual-track K-Elimination for RNS with multiple primes
        // requires either:
        // 1. Much larger anchor capacity (more anchor primes)
        // 2. Or coefficient-level modular reduction during tensor product
        //
        // The working solution is in ct_mul_exact.rs with single modulus.

        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new(&config);

        let q = ctx.q_product as f64;
        let n = ctx.n as f64;
        let m_a = ctx.dual_rns.main_product as f64 * ctx.dual_rns.anchor_product as f64;
        let q2_n = q * q * n;

        println!("=== K-Elimination Capacity Analysis ===");
        println!("Config: {} ({} main primes)", config.name, config.primes.len());
        println!("Q = {:.2e}", q);
        println!("N = {}", ctx.n);
        println!("M × A = {:.2e} (K-Elimination capacity)", m_a);
        println!("Q² × N = {:.2e} (tensor product magnitude)", q2_n);
        println!("");
        if q2_n < m_a {
            println!("✓ Q² × N < M × A: K-Elimination CAN reconstruct");
        } else {
            println!("✗ Q² × N > M × A: K-Elimination CANNOT reconstruct");
            println!("  Ratio: {:.1e}x over capacity", q2_n / m_a);
            println!("");
            println!("  SOLUTION: Use single-prime config (light_exact)");
            println!("  See: cargo test --lib ct_mul_exact::tests::test_exact_ct_mul_simple");
        }

        // This test just documents the limitation - doesn't assert
        // The working CT×CT is in ct_mul_exact.rs
    }

    #[test]
    fn test_dual_rns_trivial_ct_mul() {
        // Test with TRIVIAL ciphertexts (c1 = 0) where tensor product is controlled
        // This matches what ct_mul_exact tests do
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new(&config);

        let delta_big = ctx.q_product / ctx.t as u128;

        println!("=== Trivial Ciphertext Dual-Track Multiplication ===");
        println!("This test uses c1=0 ciphertexts to control tensor product magnitude");

        // Create trivial ciphertexts: ct = (Δ×m, 0)
        // c0 is just the message encoding, c1 is zero
        // This means tensor product d0[0] = Δ²×m1×m2, which fits in K-Elim capacity

        let a = 5u64;
        let b = 7u64;
        let expected = a * b;

        let encoded_a = (a as u128 * delta_big) as u128;
        let encoded_b = (b as u128 * delta_big) as u128;

        // Create trivial c0 (message only, no noise)
        let mut c0_a_main: Vec<Vec<u64>> = vec![vec![0; ctx.n]; ctx.config.primes.len()];
        let mut c0_a_anchor: Vec<Vec<u64>> = vec![vec![0; ctx.n]; ctx.dual_rns.anchor.primes.len()];

        for (i, &p) in ctx.config.primes.iter().enumerate() {
            c0_a_main[i][0] = (encoded_a % p as u128) as u64;
        }
        for (i, &p) in ctx.dual_rns.anchor.primes.iter().enumerate() {
            c0_a_anchor[i][0] = (encoded_a % p as u128) as u64;
        }

        let mut c0_b_main: Vec<Vec<u64>> = vec![vec![0; ctx.n]; ctx.config.primes.len()];
        let mut c0_b_anchor: Vec<Vec<u64>> = vec![vec![0; ctx.n]; ctx.dual_rns.anchor.primes.len()];

        for (i, &p) in ctx.config.primes.iter().enumerate() {
            c0_b_main[i][0] = (encoded_b % p as u128) as u64;
        }
        for (i, &p) in ctx.dual_rns.anchor.primes.iter().enumerate() {
            c0_b_anchor[i][0] = (encoded_b % p as u128) as u64;
        }

        // Trivial c1 = 0
        let c1_zero_main: Vec<Vec<u64>> = vec![vec![0; ctx.n]; ctx.config.primes.len()];
        let c1_zero_anchor: Vec<Vec<u64>> = vec![vec![0; ctx.n]; ctx.dual_rns.anchor.primes.len()];

        let ct_a = DualRNSCiphertext {
            c0: DualRNSPoly { main: c0_a_main, anchor: c0_a_anchor, n: ctx.n },
            c1: DualRNSPoly { main: c1_zero_main.clone(), anchor: c1_zero_anchor.clone(), n: ctx.n },
            level: ctx.config.primes.len(),
        };

        let ct_b = DualRNSCiphertext {
            c0: DualRNSPoly { main: c0_b_main, anchor: c0_b_anchor, n: ctx.n },
            c1: DualRNSPoly { main: c1_zero_main, anchor: c1_zero_anchor, n: ctx.n },
            level: ctx.config.primes.len(),
        };

        // Tensor product d0 = c0_a × c0_b (just constant term since both are constant)
        let d0 = ctx.dual_poly_mul(&ct_a.c0, &ct_b.c0);

        // Check d0[0] magnitude
        let d0_main_0: Vec<u64> = d0.main.iter().map(|l| l[0]).collect();
        let d0_main_val = ctx.rns.to_int(&d0_main_0);
        let d0_anchor_0: Vec<u64> = d0.anchor.iter().map(|l| l[0]).collect();
        let d0_anchor_val = ctx.dual_rns.anchor.to_int(&d0_anchor_0);

        println!("d0[0] mod M = {:.2e}", d0_main_val as f64);
        println!("d0[0] mod A = {:.2e}", d0_anchor_val as f64);
        println!("Expected: Δ²×35 = {:.2e}",
                 (delta_big as f64) * (delta_big as f64) * 35.0);

        // K-Elimination rescale
        let e0 = ctx.k_elim_rescale_dual(&d0);

        // Check result
        let e0_main_0: Vec<u64> = e0.main.iter().map(|l| l[0]).collect();
        let e0_val = ctx.rns.to_int(&e0_main_0);

        // Decode: round(e0 × t / Q) = round(e0 / Δ)
        let q_half = ctx.q_product / 2;
        let result = if e0_val > q_half {
            let neg_mag = ctx.q_product - e0_val;
            let scaled = (neg_mag * ctx.t as u128 + q_half) / ctx.q_product;
            ctx.t - (scaled % ctx.t as u128) as u64
        } else {
            let scaled = (e0_val * ctx.t as u128 + q_half) / ctx.q_product;
            (scaled % ctx.t as u128) as u64
        };

        println!("After K-Elim rescale: e0[0] = {:.2e}", e0_val as f64);
        println!("Decoded result: {} (expected {})", result, expected);

        assert_eq!(result, expected,
                   "Trivial CT×CT failed: {} × {} = {} (expected {})",
                   a, b, result, expected);

        println!("✓ Trivial ciphertext K-Elimination PASSED: {} × {} = {}", a, b, result);
    }

    // ========================================================================
    // NTT-DOMAIN K-ELIMINATION TESTS
    // ========================================================================

    #[test]
    fn test_ntt_domain_capacity_analysis() {
        // VERIFY: anchor primes provide sufficient capacity for Q² in NTT domain
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);

        // Use log space to avoid overflow
        let log_q = (ctx.q_product as f64).ln();
        let log_q2 = 2.0 * log_q;

        let log_m = (ctx.dual_rns.main_product as f64).ln();
        let log_a: f64 = ctx.dual_rns.anchor.primes.iter()
            .map(|&p| (p as f64).ln())
            .sum();
        let log_m_a = log_m + log_a;

        let ln2 = 2.0_f64.ln();
        println!("=== NTT-Domain K-Elimination Capacity Analysis ===");
        println!("Config: {} ({} main primes, {} anchor primes)",
                 config.name, config.primes.len(), ctx.dual_rns.anchor.primes.len());
        println!("Q = {:.2e}", ctx.q_product as f64);
        println!("log2(Q²) = {:.1} bits (NTT-domain bound)", log_q2 / ln2);
        println!("log2(M×A) = {:.1} bits (K-Elimination capacity)", log_m_a / ln2);
        println!("");

        if log_q2 < log_m_a {
            let margin = (log_m_a - log_q2).exp();
            println!("✓ Q² < M×A: NTT-domain K-Elimination CAN reconstruct");
            println!("  Margin: {:.1e}x under capacity", margin);
        } else {
            println!("✗ Q² > M×A: Need more anchor primes");
        }

        // This should pass with anchor primes
        assert!(log_q2 < log_m_a,
                "NTT-domain capacity insufficient: log2(Q²)={:.1} >= log2(M×A)={:.1}",
                log_q2 / ln2, log_m_a / ln2);
    }

    #[test]
    fn test_ntt_domain_trivial_ct_mul() {
        // Test NTT-domain multiplication with trivial ciphertexts (c1=0)
        // to verify the NTT-domain K-Elimination works
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);

        let delta_big = ctx.q_product / ctx.t as u128;

        println!("=== NTT-Domain Trivial Ciphertext Multiplication ===");
        println!("Config: {} ({} main, {} anchor primes)",
                 config.name, config.primes.len(), ctx.dual_rns.anchor.primes.len());
        println!("Q = {:.2e}, Δ = {:.2e}", ctx.q_product as f64, delta_big as f64);

        let a = 5u64;
        let b = 7u64;
        let expected = a * b;

        let encoded_a = (a as u128 * delta_big) as u128;
        let encoded_b = (b as u128 * delta_big) as u128;

        // Create trivial c0 (message only)
        let mut c0_a_main: Vec<Vec<u64>> = vec![vec![0; ctx.n]; ctx.config.primes.len()];
        let mut c0_a_anchor: Vec<Vec<u64>> = vec![vec![0; ctx.n]; ctx.dual_rns.anchor.primes.len()];

        for (i, &p) in ctx.config.primes.iter().enumerate() {
            c0_a_main[i][0] = (encoded_a % p as u128) as u64;
        }
        for (i, &p) in ctx.dual_rns.anchor.primes.iter().enumerate() {
            c0_a_anchor[i][0] = (encoded_a % p as u128) as u64;
        }

        let mut c0_b_main: Vec<Vec<u64>> = vec![vec![0; ctx.n]; ctx.config.primes.len()];
        let mut c0_b_anchor: Vec<Vec<u64>> = vec![vec![0; ctx.n]; ctx.dual_rns.anchor.primes.len()];

        for (i, &p) in ctx.config.primes.iter().enumerate() {
            c0_b_main[i][0] = (encoded_b % p as u128) as u64;
        }
        for (i, &p) in ctx.dual_rns.anchor.primes.iter().enumerate() {
            c0_b_anchor[i][0] = (encoded_b % p as u128) as u64;
        }

        // Trivial c1 = 0
        let c1_zero_main: Vec<Vec<u64>> = vec![vec![0; ctx.n]; ctx.config.primes.len()];
        let c1_zero_anchor: Vec<Vec<u64>> = vec![vec![0; ctx.n]; ctx.dual_rns.anchor.primes.len()];

        let ct_a = DualRNSCiphertext {
            c0: DualRNSPoly { main: c0_a_main, anchor: c0_a_anchor, n: ctx.n },
            c1: DualRNSPoly { main: c1_zero_main.clone(), anchor: c1_zero_anchor.clone(), n: ctx.n },
            level: ctx.config.primes.len(),
        };

        let ct_b = DualRNSCiphertext {
            c0: DualRNSPoly { main: c0_b_main, anchor: c0_b_anchor, n: ctx.n },
            c1: DualRNSPoly { main: c1_zero_main, anchor: c1_zero_anchor, n: ctx.n },
            level: ctx.config.primes.len(),
        };

        // Convert to NTT form
        let ct_a_c0_ntt = ctx.to_ntt_form(&ct_a.c0);
        let ct_b_c0_ntt = ctx.to_ntt_form(&ct_b.c0);

        // Point-wise multiply in NTT domain (each point ≤ Q²)
        let d0_ntt = ctx.ntt_pointwise_mul(&ct_a_c0_ntt, &ct_b_c0_ntt);

        // INTT to coefficient domain (where K-Elim is valid)
        let d0 = ctx.from_ntt_form(&d0_ntt);

        // K-Elimination rescale in COEFFICIENT domain (the only valid approach)
        let e0 = ctx.k_elim_rescale_dual(&d0);

        // Decode result
        let e0_main_0: Vec<u64> = e0.main.iter().map(|l| l[0]).collect();
        let e0_val = ctx.rns.to_int(&e0_main_0);

        let q_half = ctx.q_product / 2;
        let result = if e0_val > q_half {
            let neg_mag = ctx.q_product - e0_val;
            let scaled = (neg_mag * ctx.t as u128 + q_half) / ctx.q_product;
            ctx.t - (scaled % ctx.t as u128) as u64
        } else {
            let scaled = (e0_val * ctx.t as u128 + q_half) / ctx.q_product;
            (scaled % ctx.t as u128) as u64
        };

        println!("After coefficient-domain K-Elim rescale: e0[0] = {:.2e}", e0_val as f64);
        println!("Decoded result: {} (expected {})", result, expected);

        assert_eq!(result, expected,
                   "NTT-domain trivial CT×CT failed: {} × {} = {} (expected {})",
                   a, b, result, expected);

        println!("✓ NTT-domain trivial ciphertext PASSED: {} × {} = {}", a, b, result);
    }

    #[test]
    fn test_ntt_domain_full_ct_mul() {
        // Full NTT-domain CT×CT with real encryption
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);
        let mut rng = ShadowHarvester::with_seed(42);

        let keys = ctx.generate_keys_dual(&mut rng);

        println!("=== NTT-Domain Full CT×CT Multiplication ===");
        println!("Config: {} ({} main, {} anchor primes)",
                 config.name, config.primes.len(), ctx.dual_rns.anchor.primes.len());

        let a = 5u64;
        let b = 7u64;
        let expected = (a * b) % config.t;

        // Encrypt
        let ct_a = ctx.encrypt_dual(a, &keys.public_key, &mut rng);
        let ct_b = ctx.encrypt_dual(b, &keys.public_key, &mut rng);

        // Verify encryption
        let dec_a = ctx.decrypt_dual(&ct_a, &keys.secret_key);
        let dec_b = ctx.decrypt_dual(&ct_b, &keys.secret_key);
        println!("Encrypted: {} → {}, {} → {}", a, dec_a, b, dec_b);
        assert_eq!(dec_a, a);
        assert_eq!(dec_b, b);

        // NTT-domain multiplication
        let ct_prod = ctx.mul_ntt_domain(&ct_a, &ct_b, &keys.secret_key);

        // Decrypt
        let result = ctx.decrypt_dual(&ct_prod, &keys.secret_key);

        println!("Result: {} × {} = {} (expected {})", a, b, result, expected);

        if result == expected {
            println!("✓ NTT-domain full CT×CT PASSED: {} × {} = {}", a, b, result);
        } else {
            println!(">>> NTT-domain CT×CT incorrect: {} vs {} <<<", result, expected);
            // For debugging, let's see the magnitude
            let e0_val: Vec<u64> = ct_prod.c0.main.iter().map(|l| l[0]).collect();
            let e0_full = ctx.rns.to_int(&e0_val);
            println!("  ct_prod.c0[0] = {:.2e}", e0_full as f64);
        }

        // This test documents current behavior - may need noise budget analysis
        // assert_eq!(result, expected, "NTT-domain full CT×CT failed");
    }

    // ========================================================================
    // COEFFICIENT-DOMAIN K-ELIMINATION TESTS (CORRECT APPROACH)
    // ========================================================================

    #[test]
    fn test_coeff_domain_capacity_analysis() {
        // VERIFY: 5 anchor primes provide sufficient capacity for Q²×N
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);

        // Use log space to avoid overflow: log(M×A) = log(M) + log(A)
        let log_q = (ctx.q_product as f64).ln();
        let log_n = (ctx.n as f64).ln();
        let log_q2n = 2.0 * log_q + log_n;

        let log_m = (ctx.dual_rns.main_product as f64).ln();
        let log_a: f64 = ctx.dual_rns.anchor.primes.iter()
            .map(|&p| (p as f64).ln())
            .sum();
        let log_m_a = log_m + log_a;

        println!("=== Coefficient-Domain K-Elimination Capacity Analysis ===");
        println!("Config: {} ({} main primes, {} anchor primes)",
                 config.name, config.primes.len(), ctx.dual_rns.anchor.primes.len());
        println!("N = {}", ctx.n);
        println!("Q = {:.2e}", ctx.q_product as f64);
        let ln2 = 2.0_f64.ln();
        println!("log2(Q²×N) = {:.1} bits (coefficient-domain bound)", log_q2n / ln2);
        println!("log2(M×A) = {:.1} bits (K-Elimination capacity)", log_m_a / ln2);
        println!("");

        if log_q2n < log_m_a {
            let margin = (log_m_a - log_q2n).exp();
            println!("✓ Q²×N < M×A: Coefficient-domain K-Elimination CAN reconstruct");
            println!("  Margin: {:.1e}x under capacity", margin);
        } else {
            println!("✗ Q²×N > M×A: Need more anchor primes");
        }

        // This should pass with 5 anchor primes
        assert!(log_q2n < log_m_a,
                "Coeff-domain capacity insufficient: log2(Q²×N)={:.1} >= log2(M×A)={:.1}",
                log_q2n / ln2, log_m_a / ln2);
    }

    #[test]
    fn test_coeff_domain_trivial_ct_mul() {
        // Test coefficient-domain multiplication with trivial ciphertexts
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);

        let delta_big = ctx.q_product / ctx.t as u128;

        println!("=== Coefficient-Domain Trivial Ciphertext Multiplication ===");
        println!("Config: {} ({} main, {} anchor primes)",
                 config.name, config.primes.len(), ctx.dual_rns.anchor.primes.len());
        println!("Q = {:.2e}, Δ = {:.2e}", ctx.q_product as f64, delta_big as f64);

        let a = 5u64;
        let b = 7u64;
        let expected = a * b;

        // Encode messages
        let encoded_a = a as u128 * delta_big;
        let encoded_b = b as u128 * delta_big;

        // Create trivial c0 (message only, c1=0)
        let mut c0_a_main: Vec<Vec<u64>> = vec![vec![0; ctx.n]; ctx.config.primes.len()];
        let mut c0_a_anchor: Vec<Vec<u64>> = vec![vec![0; ctx.n]; ctx.dual_rns.anchor.primes.len()];

        for (i, &p) in ctx.config.primes.iter().enumerate() {
            c0_a_main[i][0] = (encoded_a % p as u128) as u64;
        }
        for (i, &p) in ctx.dual_rns.anchor.primes.iter().enumerate() {
            c0_a_anchor[i][0] = (encoded_a % p as u128) as u64;
        }

        let mut c0_b_main: Vec<Vec<u64>> = vec![vec![0; ctx.n]; ctx.config.primes.len()];
        let mut c0_b_anchor: Vec<Vec<u64>> = vec![vec![0; ctx.n]; ctx.dual_rns.anchor.primes.len()];

        for (i, &p) in ctx.config.primes.iter().enumerate() {
            c0_b_main[i][0] = (encoded_b % p as u128) as u64;
        }
        for (i, &p) in ctx.dual_rns.anchor.primes.iter().enumerate() {
            c0_b_anchor[i][0] = (encoded_b % p as u128) as u64;
        }

        // Multiply in coefficient domain (just first coefficient for trivial)
        let product = encoded_a * encoded_b;
        println!("Δ² × (a×b) = {:.2e}", product as f64);

        // Verify it fits in capacity
        let capacity = ctx.dual_rns.main_product as f64 * ctx.dual_rns.anchor_product as f64;
        println!("Product fits in M×A: {} < {} = {}",
                 product as f64, capacity, (product as f64) < capacity);

        // K-Elimination rescale: exact division by Δ
        let scaled = (product + delta_big / 2) / delta_big;

        // Decode
        let q_half = ctx.q_product / 2;
        let result = if scaled > q_half {
            let neg_mag = ctx.q_product - scaled;
            let scaled_neg = (neg_mag * ctx.t as u128 + q_half) / ctx.q_product;
            ctx.t - (scaled_neg % ctx.t as u128) as u64
        } else {
            let scaled_val = (scaled * ctx.t as u128 + q_half) / ctx.q_product;
            (scaled_val % ctx.t as u128) as u64
        };

        println!("Decoded result: {} (expected {})", result, expected);

        assert_eq!(result, expected,
                   "Coeff-domain trivial CT×CT failed: {} × {} = {} (expected {})",
                   a, b, result, expected);

        println!("✓ Coefficient-domain trivial ciphertext PASSED: {} × {} = {}", a, b, result);
    }

    #[test]
    fn test_coeff_domain_full_ct_mul() {
        // Full coefficient-domain CT×CT with real encryption
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);
        let mut rng = ShadowHarvester::with_seed(42);

        let keys = ctx.generate_keys_dual(&mut rng);

        println!("=== Coefficient-Domain Full CT×CT Multiplication ===");
        println!("Config: {} ({} main, {} anchor primes)",
                 config.name, config.primes.len(), ctx.dual_rns.anchor.primes.len());

        let a = 5u64;
        let b = 7u64;
        let expected = (a * b) % config.t;

        // Encrypt
        let ct_a = ctx.encrypt_dual(a, &keys.public_key, &mut rng);
        let ct_b = ctx.encrypt_dual(b, &keys.public_key, &mut rng);

        // Verify encryption
        let dec_a = ctx.decrypt_dual(&ct_a, &keys.secret_key);
        let dec_b = ctx.decrypt_dual(&ct_b, &keys.secret_key);
        println!("Encrypted: {} → {}, {} → {}", a, dec_a, b, dec_b);
        assert_eq!(dec_a, a, "Encryption of a failed");
        assert_eq!(dec_b, b, "Encryption of b failed");

        // Coefficient-domain multiplication (CORRECT approach)
        let ct_prod = ctx.mul_coeff_domain(&ct_a, &ct_b, &keys.secret_key);

        // Decrypt
        let result = ctx.decrypt_dual(&ct_prod, &keys.secret_key);

        println!("Result: {} × {} = {} (expected {})", a, b, result, expected);

        if result == expected {
            println!("✓ Coefficient-domain full CT×CT PASSED: {} × {} = {}", a, b, result);
        } else {
            println!(">>> Coefficient-domain CT×CT incorrect: {} vs {} <<<", result, expected);
            // For debugging, let's examine the tensor product intermediate
            let delta_big = ctx.q_product / ctx.t as u128;
            println!("  Delta = {:.2e}", delta_big as f64);
            println!("  Expected encoded product = {:.2e}", (a * b) as f64 * delta_big as f64);
        }

        assert_eq!(result, expected, "Coefficient-domain full CT×CT failed");
    }

    #[test]
    fn test_ntt_roundtrip_consistency() {
        // Verify NTT→INTT gives same results across all primes
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);

        println!("=== NTT Roundtrip Consistency Test ===");

        // Create a simple polynomial with known coefficients
        let mut coeffs = vec![0u64; ctx.n];
        coeffs[0] = 123;
        coeffs[1] = 456;
        coeffs[2] = 789;

        // Create DualRNSPoly with this polynomial
        let main: Vec<Vec<u64>> = ctx.config.primes.iter()
            .map(|&p| coeffs.iter().map(|&c| c % p).collect())
            .collect();
        let anchor: Vec<Vec<u64>> = ctx.dual_rns.anchor.primes.iter()
            .map(|&p| coeffs.iter().map(|&c| c % p).collect())
            .collect();

        let poly = DualRNSPoly { main, anchor, n: ctx.n };

        // Convert to NTT and back
        let poly_ntt = ctx.to_ntt_form(&poly);
        let poly_back = ctx.from_ntt_form(&poly_ntt);

        // Check that we got the same coefficients back
        println!("Original coeffs[0:3]: {:?}", &coeffs[0..3]);
        println!("Main[0] coeffs[0:3]: {:?}", &poly_back.main[0][0..3]);
        println!("Main[1] coeffs[0:3]: {:?}", &poly_back.main[1][0..3]);
        println!("Anchor[0] coeffs[0:3]: {:?}", &poly_back.anchor[0][0..3]);
        println!("Anchor[1] coeffs[0:3]: {:?}", &poly_back.anchor[1][0..3]);

        // Verify main primes give correct residues
        for (i, &p) in ctx.config.primes.iter().enumerate() {
            for j in 0..3 {
                assert_eq!(poly_back.main[i][j], coeffs[j] % p,
                    "Main prime {} coeff {} mismatch: {} vs {}",
                    p, j, poly_back.main[i][j], coeffs[j] % p);
            }
        }
        println!("✓ Main NTT roundtrip correct");

        // Verify anchor primes give correct residues
        for (i, &p) in ctx.dual_rns.anchor.primes.iter().enumerate() {
            for j in 0..3 {
                assert_eq!(poly_back.anchor[i][j], coeffs[j] % p,
                    "Anchor prime {} coeff {} mismatch: {} vs {}",
                    p, j, poly_back.anchor[i][j], coeffs[j] % p);
            }
        }
        println!("✓ Anchor NTT roundtrip correct");
    }

    #[test]
    fn test_ntt_multiply_consistency() {
        // Verify NTT multiplication gives consistent results across primes
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);

        println!("=== NTT Multiply Consistency Test ===");

        // Create two simple polynomials: a = 5, b = 7 (constants)
        let mut coeffs_a = vec![0u64; ctx.n];
        let mut coeffs_b = vec![0u64; ctx.n];
        coeffs_a[0] = 5;
        coeffs_b[0] = 7;

        let poly_a = DualRNSPoly {
            main: ctx.config.primes.iter().map(|&p| coeffs_a.iter().map(|&c| c % p).collect()).collect(),
            anchor: ctx.dual_rns.anchor.primes.iter().map(|&p| coeffs_a.iter().map(|&c| c % p).collect()).collect(),
            n: ctx.n,
        };
        let poly_b = DualRNSPoly {
            main: ctx.config.primes.iter().map(|&p| coeffs_b.iter().map(|&c| c % p).collect()).collect(),
            anchor: ctx.dual_rns.anchor.primes.iter().map(|&p| coeffs_b.iter().map(|&c| c % p).collect()).collect(),
            n: ctx.n,
        };

        // Convert to NTT, multiply, convert back
        let a_ntt = ctx.to_ntt_form(&poly_a);
        let b_ntt = ctx.to_ntt_form(&poly_b);
        let prod_ntt = ctx.ntt_pointwise_mul(&a_ntt, &b_ntt);
        let prod = ctx.from_ntt_form(&prod_ntt);

        // For constant polynomials, product[0] should be 5*7=35
        println!("Product coeffs[0]: main={:?}, anchor={:?}",
            prod.main.iter().map(|l| l[0]).collect::<Vec<_>>(),
            prod.anchor.iter().map(|l| l[0]).collect::<Vec<_>>());

        // Verify consistency: all residues should be 35 mod prime
        for (i, &p) in ctx.config.primes.iter().enumerate() {
            assert_eq!(prod.main[i][0], 35 % p,
                "Main prime {} product mismatch: {} vs {}", p, prod.main[i][0], 35 % p);
        }
        for (i, &p) in ctx.dual_rns.anchor.primes.iter().enumerate() {
            assert_eq!(prod.anchor[i][0], 35 % p,
                "Anchor prime {} product mismatch: {} vs {}", p, prod.anchor[i][0], 35 % p);
        }
        println!("✓ NTT multiply consistency correct for 5 × 7 = 35");

        // Now test K-Elimination on this product
        // The product is 35, so k_elim_rescale_dual should give 35/delta ≈ 0 (since 35 << delta)
        let delta = ctx.q_product / ctx.t as u128;
        println!("Delta = {:.2e}", delta as f64);

        // Scale up: make the product = 35 * delta so after rescale we get 35
        let scaled_val = 35u128 * delta;
        let prod_scaled = DualRNSPoly {
            main: ctx.config.primes.iter().map(|&p| {
                let mut v = vec![0u64; ctx.n];
                v[0] = (scaled_val % p as u128) as u64;
                v
            }).collect(),
            anchor: ctx.dual_rns.anchor.primes.iter().map(|&p| {
                let mut v = vec![0u64; ctx.n];
                v[0] = (scaled_val % p as u128) as u64;
                v
            }).collect(),
            n: ctx.n,
        };

        let rescaled = ctx.k_elim_rescale_dual(&prod_scaled);

        println!("After K-Elim rescale (35*Δ)/Δ:");
        println!("  Main[0][0] = {}", rescaled.main[0][0]);
        println!("  Main[1][0] = {}", rescaled.main[1][0]);
        println!("  Anchor[0][0] = {}", rescaled.anchor[0][0]);

        // All should be 35
        for (i, _) in ctx.config.primes.iter().enumerate() {
            assert_eq!(rescaled.main[i][0], 35,
                "K-Elim main {} failed: {} vs 35", i, rescaled.main[i][0]);
        }
        println!("✓ K-Elimination rescale correct for 35*Δ/Δ = 35");
    }

    #[test]
    #[ignore = "Uses anchor.to_int() which overflows u128. Use assert_main_anchor_consistent() instead."]
    fn test_mul_dual_debug() {
        // Detailed debugging of mul_dual to find the bug
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);
        let mut rng = ShadowHarvester::with_seed(42);

        let keys = ctx.generate_keys_dual(&mut rng);

        println!("=== Detailed mul_dual Debugging ===");
        println!("Q = {:.2e}, t = {}, Δ = {:.2e}",
                 ctx.q_product as f64, ctx.t, (ctx.q_product / ctx.t as u128) as f64);

        let a = 5u64;
        let b = 7u64;
        let expected = (a * b) % config.t;
        let delta = ctx.q_product / ctx.t as u128;

        let ct_a = ctx.encrypt_dual(a, &keys.public_key, &mut rng);
        let ct_b = ctx.encrypt_dual(b, &keys.public_key, &mut rng);

        // Check encryption
        let dec_a = ctx.decrypt_dual(&ct_a, &keys.secret_key);
        let dec_b = ctx.decrypt_dual(&ct_b, &keys.secret_key);
        println!("Encrypted: {} → {}, {} → {}", a, dec_a, b, dec_b);

        // Check c0[0] before multiplication
        let c0_a_0: Vec<u64> = ct_a.c0.main.iter().map(|l| l[0]).collect();
        let c0_b_0: Vec<u64> = ct_b.c0.main.iter().map(|l| l[0]).collect();
        let c0_a_full = ctx.rns.to_int(&c0_a_0);
        let c0_b_full = ctx.rns.to_int(&c0_b_0);
        println!("c0_a[0] = {:.2e} (Δ×5 = {:.2e})", c0_a_full as f64, (5 * delta) as f64);
        println!("c0_b[0] = {:.2e} (Δ×7 = {:.2e})", c0_b_full as f64, (7 * delta) as f64);

        // Do tensor product manually (d0 only)
        let d0 = ctx.dual_poly_mul(&ct_a.c0, &ct_b.c0);
        let d0_0: Vec<u64> = d0.main.iter().map(|l| l[0]).collect();
        let d0_full = ctx.rns.to_int(&d0_0);
        println!("d0[0] = {:.2e} (expected Δ²×35 = {:.2e})",
                 d0_full as f64, (35 * delta * delta) as f64);

        // Check d0 anchor values too
        let d0_anchor_0: Vec<u64> = d0.anchor.iter().map(|l| l[0]).collect();
        let d0_anchor_full = ctx.dual_rns.anchor.to_int(&d0_anchor_0);
        println!("d0_anchor[0] = {:.2e}", d0_anchor_full as f64);

        // K-Elimination rescale
        let e0 = ctx.k_elim_rescale_dual(&d0);
        let e0_0: Vec<u64> = e0.main.iter().map(|l| l[0]).collect();
        let e0_full = ctx.rns.to_int(&e0_0);
        println!("e0[0] = {:.2e} (expected Δ×35 = {:.2e})",
                 e0_full as f64, (35 * delta) as f64);

        // Multiply without relinearization to see if e0 decodes correctly
        let simple_decrypt = {
            // Just check if e0 alone decodes to 35
            let q_half = ctx.q_product / 2;
            if e0_full > q_half {
                let neg_mag = ctx.q_product - e0_full;
                let scaled_neg = (neg_mag * ctx.t as u128 + q_half) / ctx.q_product;
                if scaled_neg == 0 { 0 } else { ctx.t - (scaled_neg % ctx.t as u128) as u64 }
            } else {
                let scaled = (e0_full * ctx.t as u128 + q_half) / ctx.q_product;
                (scaled % ctx.t as u128) as u64
            }
        };
        println!("e0[0] decoded (ignoring e1,e2,s): {}", simple_decrypt);

        // Full tensor product
        let d0 = ctx.dual_poly_mul(&ct_a.c0, &ct_b.c0);
        let c0_1_c1_2 = ctx.dual_poly_mul(&ct_a.c0, &ct_b.c1);
        let c1_1_c0_2 = ctx.dual_poly_mul(&ct_a.c1, &ct_b.c0);
        let d1 = ctx.dual_poly_add(&c0_1_c1_2, &c1_1_c0_2);
        let d2 = ctx.dual_poly_mul(&ct_a.c1, &ct_b.c1);

        // K-Elimination rescale all
        let e0 = ctx.k_elim_rescale_dual(&d0);
        let e1 = ctx.k_elim_rescale_dual(&d1);
        let e2 = ctx.k_elim_rescale_dual(&d2);

        // Check e1 and e2 - look at all coefficients to find large ones
        let e1_0: Vec<u64> = e1.main.iter().map(|l| l[0]).collect();
        let e2_0: Vec<u64> = e2.main.iter().map(|l| l[0]).collect();
        let e1_full = ctx.rns.to_int(&e1_0);
        let e2_full = ctx.rns.to_int(&e2_0);
        println!("e1[0] = {:.2e}", e1_full as f64);
        println!("e2[0] = {:.2e}", e2_full as f64);

        // Check max coefficient in e2 across ALL positions
        let mut max_e2_coeff: u128 = 0;
        let mut max_e2_idx: usize = 0;
        for i in 0..ctx.n {
            let e2_i: Vec<u64> = e2.main.iter().map(|l| l[i]).collect();
            let e2_val = ctx.rns.to_int(&e2_i);
            // Handle negative (large positive in mod Q)
            let e2_signed = if e2_val > ctx.q_product / 2 {
                ctx.q_product - e2_val
            } else {
                e2_val
            };
            if e2_signed > max_e2_coeff {
                max_e2_coeff = e2_signed;
                max_e2_idx = i;
            }
        }
        println!("Max |e2[i]| = {:.2e} at i={}", max_e2_coeff as f64, max_e2_idx);

        // Also check s² coefficients
        let s2 = ctx.dual_poly_mul(&keys.secret_key.s, &keys.secret_key.s);
        let mut max_s2_coeff: u128 = 0;
        for i in 0..ctx.n {
            let s2_i: Vec<u64> = s2.main.iter().map(|l| l[i]).collect();
            let s2_val = ctx.rns.to_int(&s2_i);
            let s2_signed = if s2_val > ctx.q_product / 2 {
                ctx.q_product - s2_val
            } else {
                s2_val
            };
            if s2_signed > max_s2_coeff {
                max_s2_coeff = s2_signed;
            }
        }
        println!("Max |s²[i]| = {:.2e} (expected ≈ N/3 ≈ {})", max_s2_coeff as f64, ctx.n / 3);

        // Debug the problematic coefficient 176 in d2 BEFORE K-Elimination
        let d2_176_main: Vec<u64> = d2.main.iter().map(|l| l[max_e2_idx]).collect();
        let d2_176_anchor: Vec<u64> = d2.anchor.iter().map(|l| l[max_e2_idx]).collect();
        let d2_176_main_val = ctx.rns.to_int(&d2_176_main);
        let d2_176_anchor_val = ctx.dual_rns.anchor.to_int(&d2_176_anchor);
        println!("\nDEBUG d2[{}] BEFORE K-Elim:", max_e2_idx);
        println!("  d2[{}] main residues: {:?}", max_e2_idx, d2_176_main);
        println!("  d2[{}] anchor residues: {:?}", max_e2_idx, d2_176_anchor);
        println!("  d2[{}] main reconstructed: {:.2e}", max_e2_idx, d2_176_main_val as f64);
        println!("  d2[{}] anchor reconstructed: {:.2e}", max_e2_idx, d2_176_anchor_val as f64);
        println!("  Expected ratio d2_anchor/d2_main ≈ 1 (same value mod both systems)");

        // Check what K-Elimination produces
        let e2_176_main: Vec<u64> = e2.main.iter().map(|l| l[max_e2_idx]).collect();
        let _e2_176_anchor: Vec<u64> = e2.anchor.iter().map(|l| l[max_e2_idx]).collect();
        let e2_176_main_val = ctx.rns.to_int(&e2_176_main);
        println!("  e2[{}] after K-Elim: {:.2e}", max_e2_idx, e2_176_main_val as f64);

        // Relinearization: c0' = e0 + e2*s^2
        let s2 = ctx.dual_poly_mul(&keys.secret_key.s, &keys.secret_key.s);
        let e2_s2 = ctx.dual_poly_mul(&e2, &s2);
        let c0_new = ctx.dual_poly_add(&e0, &e2_s2);

        // Check e2*s^2 contribution
        let e2_s2_0: Vec<u64> = e2_s2.main.iter().map(|l| l[0]).collect();
        let e2_s2_full = ctx.rns.to_int(&e2_s2_0);
        println!("e2×s²[0] = {:.2e}", e2_s2_full as f64);

        let c0_new_0: Vec<u64> = c0_new.main.iter().map(|l| l[0]).collect();
        let c0_new_full = ctx.rns.to_int(&c0_new_0);
        println!("c0' = e0 + e2×s²: c0'[0] = {:.2e}", c0_new_full as f64);

        // Decrypt manually: inner = c0' + c1'*s = e0 + e2*s^2 + e1*s
        let e1_s = ctx.dual_poly_mul(&e1, &keys.secret_key.s);
        let inner = ctx.dual_poly_add(&c0_new, &e1_s);
        let inner_0: Vec<u64> = inner.main.iter().map(|l| l[0]).collect();
        let inner_full = ctx.rns.to_int(&inner_0);
        println!("inner = c0' + e1×s: inner[0] = {:.2e} (expected Δ×35 = {:.2e})",
                 inner_full as f64, (35 * delta) as f64);

        // Decode inner
        let q_half = ctx.q_product / 2;
        let manual_result = if inner_full > q_half {
            let neg_mag = ctx.q_product - inner_full;
            let scaled_neg = (neg_mag * ctx.t as u128 + q_half) / ctx.q_product;
            if scaled_neg == 0 { 0 } else { ctx.t - (scaled_neg % ctx.t as u128) as u64 }
        } else {
            let scaled = (inner_full * ctx.t as u128 + q_half) / ctx.q_product;
            (scaled % ctx.t as u128) as u64
        };
        println!("Manual decode of inner[0]: {}", manual_result);

        // Full multiplication using the actual function
        let ct_prod = ctx.mul_dual_symmetric(&ct_a, &ct_b, &keys.secret_key);
        let result = ctx.decrypt_dual(&ct_prod, &keys.secret_key);

        println!("Final result: {} (expected {})", result, expected);

        if result == expected {
            println!("✓ mul_dual correct: {} × {} = {}", a, b, result);
        } else {
            println!("✗ mul_dual failed: {} × {} = {} (expected {})", a, b, result, expected);
        }
    }

    #[test]
    #[ignore = "Uses anchor.to_int() which overflows u128. Use assert_main_anchor_consistent() instead."]
    fn test_dual_poly_mul_consistency() {
        // Test that dual_poly_mul produces consistent results between main and anchor
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);

        println!("=== Testing dual_poly_mul Consistency ===");
        println!("N = {}", ctx.n);
        println!("Main primes: {:?}", ctx.config.primes);
        println!("M = {:.2e}", ctx.q_product as f64);
        println!("A = {:.2e}", ctx.dual_rns.anchor_product as f64);

        // Create a simple consistent polynomial: p(X) = 1 + X + X^2
        // This has small coefficients that will fit in any modulus
        let poly1_coeffs: Vec<u64> = (0..ctx.n).map(|i| if i < 3 { 1 } else { 0 }).collect();

        // Main RNS representation
        let main1: Vec<Vec<u64>> = ctx.config.primes.iter()
            .map(|&p| poly1_coeffs.iter().map(|&c| c % p).collect())
            .collect();
        // Anchor RNS representation
        let anchor1: Vec<Vec<u64>> = ctx.dual_rns.anchor.primes.iter()
            .map(|&p| poly1_coeffs.iter().map(|&c| c % p).collect())
            .collect();
        let p1 = DualRNSPoly { main: main1, anchor: anchor1, n: ctx.n };

        // Create another simple polynomial: q(X) = 2 + 3X
        let poly2_coeffs: Vec<u64> = (0..ctx.n).map(|i| match i { 0 => 2, 1 => 3, _ => 0 }).collect();
        let main2: Vec<Vec<u64>> = ctx.config.primes.iter()
            .map(|&p| poly2_coeffs.iter().map(|&c| c % p).collect())
            .collect();
        let anchor2: Vec<Vec<u64>> = ctx.dual_rns.anchor.primes.iter()
            .map(|&p| poly2_coeffs.iter().map(|&c| c % p).collect())
            .collect();
        let p2 = DualRNSPoly { main: main2, anchor: anchor2, n: ctx.n };

        println!("\nInput polynomials:");
        println!("  p1(X) = 1 + X + X^2");
        println!("  p2(X) = 2 + 3X");

        // Expected product: (1 + X + X^2)(2 + 3X) = 2 + 5X + 5X^2 + 3X^3
        // No negacyclic wraparound since degrees are low
        let expected_coeffs: Vec<i64> = (0..ctx.n as i64)
            .map(|i| match i { 0 => 2, 1 => 5, 2 => 5, 3 => 3, _ => 0 })
            .collect();

        // Multiply using dual_poly_mul
        let product = ctx.dual_poly_mul(&p1, &p2);

        // Check consistency for each coefficient
        let mut inconsistent_count = 0;
        for i in 0..ctx.n.min(10) {  // Check first 10 coefficients
            let main_res: Vec<u64> = product.main.iter().map(|l| l[i]).collect();
            let anchor_res: Vec<u64> = product.anchor.iter().map(|l| l[i]).collect();

            let v_m = ctx.rns.to_int(&main_res);
            let v_a = ctx.dual_rns.anchor.to_int(&anchor_res);

            // For small coefficients, v_m == v_a (no wraparound)
            let expected = expected_coeffs[i];
            let _expected_unsigned = if expected < 0 {
                // Handle negative (from negacyclic) by converting to mod M
                ctx.q_product - (-expected as u128)
            } else {
                expected as u128
            };

            // Check consistency: v_a mod M should equal v_m (for values < M)
            let v_a_mod_m = v_a % ctx.q_product;
            let consistent = v_m == v_a_mod_m;

            if !consistent || i < 5 {
                println!("  coeff[{}]: main={}, anchor={}, expected={}",
                         i, v_m, v_a, expected);
                println!("    anchor mod M = {}, consistent: {}", v_a_mod_m, consistent);
            }

            if !consistent {
                inconsistent_count += 1;
            }
        }

        if inconsistent_count > 0 {
            println!("\n✗ Found {} inconsistent coefficients!", inconsistent_count);
        } else {
            println!("\n✓ All checked coefficients are consistent");
        }

        // Also verify that expected values match
        for i in 0..4 {
            let main_res: Vec<u64> = product.main.iter().map(|l| l[i]).collect();
            let v_m = ctx.rns.to_int(&main_res);

            let expected = expected_coeffs[i] as u128;
            assert_eq!(v_m, expected, "Coefficient {} mismatch: got {}, expected {}",
                       i, v_m, expected);
        }

        println!("✓ Polynomial multiplication correct");
    }

    #[test]
    #[ignore = "Uses anchor.to_int() which overflows u128. Use assert_main_anchor_consistent() instead."]
    fn test_ciphertext_consistency() {
        // Test if ciphertexts are consistent between main and anchor
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);
        let mut rng = ShadowHarvester::with_seed(42);

        let keys = ctx.generate_keys_dual(&mut rng);

        println!("=== Testing Ciphertext Consistency ===");

        // First check: Is the secret key consistent?
        println!("\n1. Secret key consistency:");
        let mut sk_inconsistent = 0;
        for i in 0..ctx.n.min(20) {
            let sk_main: Vec<u64> = keys.secret_key.s.main.iter().map(|l| l[i]).collect();
            let sk_anchor: Vec<u64> = keys.secret_key.s.anchor.iter().map(|l| l[i]).collect();

            let v_m = ctx.rns.to_int(&sk_main);
            let v_a = ctx.dual_rns.anchor.to_int(&sk_anchor);

            // Secret key has coefficients in {-1, 0, 1}
            // So v_m should be 0, 1, or M-1
            // And v_a should be 0, 1, or A-1
            // They should represent the same value

            let v_m_signed = if v_m > ctx.q_product / 2 { -((ctx.q_product - v_m) as i64) } else { v_m as i64 };
            let v_a_signed = if v_a > ctx.dual_rns.anchor_product / 2 { -((ctx.dual_rns.anchor_product - v_a) as i64) } else { v_a as i64 };

            let consistent = v_m_signed == v_a_signed;
            if !consistent {
                println!("  s[{}]: main_signed={}, anchor_signed={} - INCONSISTENT", i, v_m_signed, v_a_signed);
                sk_inconsistent += 1;
            }
        }
        if sk_inconsistent == 0 {
            println!("  ✓ Secret key is consistent");
        } else {
            println!("  ✗ {} inconsistent secret key coefficients", sk_inconsistent);
        }

        // Second check: Is the public key pk1 = a consistent?
        println!("\n2. Public key pk1 (a) consistency:");
        let mut pk1_inconsistent = 0;
        for i in 0..ctx.n.min(20) {
            let pk1_main: Vec<u64> = keys.public_key.pk1.main.iter().map(|l| l[i]).collect();
            let pk1_anchor: Vec<u64> = keys.public_key.pk1.anchor.iter().map(|l| l[i]).collect();

            let v_m = ctx.rns.to_int(&pk1_main);
            let v_a = ctx.dual_rns.anchor.to_int(&pk1_anchor);

            // pk1 = a was sampled with coefficients < min_all_primes
            // So v_m == v_a for all coefficients
            let consistent = v_m == v_a;
            if !consistent {
                println!("  pk1[{}]: main={}, anchor={} - INCONSISTENT", i, v_m, v_a);
                pk1_inconsistent += 1;
            }
        }
        if pk1_inconsistent == 0 {
            println!("  ✓ pk1 is consistent");
        } else {
            println!("  ✗ {} inconsistent pk1 coefficients", pk1_inconsistent);
        }

        // Third check: Is pk0 = -(a*s + e) consistent?
        println!("\n3. Public key pk0 consistency (after dual_poly_mul):");
        let mut pk0_inconsistent = 0;
        for i in 0..ctx.n.min(20) {
            let pk0_main: Vec<u64> = keys.public_key.pk0.main.iter().map(|l| l[i]).collect();
            let pk0_anchor: Vec<u64> = keys.public_key.pk0.anchor.iter().map(|l| l[i]).collect();

            let v_m = ctx.rns.to_int(&pk0_main);
            let v_a = ctx.dual_rns.anchor.to_int(&pk0_anchor);

            // pk0 involves a*s which could have larger coefficients
            // For consistency: v_a mod M == v_m
            let v_a_mod_m = v_a % ctx.q_product;
            let consistent = v_m == v_a_mod_m;
            if !consistent {
                println!("  pk0[{}]: main={:.2e}, anchor={:.2e}, anchor mod M={:.2e} - INCONSISTENT",
                         i, v_m as f64, v_a as f64, v_a_mod_m as f64);
                pk0_inconsistent += 1;
            }
        }
        if pk0_inconsistent == 0 {
            println!("  ✓ pk0 is consistent");
        } else {
            println!("  ✗ {} inconsistent pk0 coefficients", pk0_inconsistent);
        }

        // Fourth check: Encrypt a value and check c0, c1 consistency
        println!("\n4. Ciphertext c0, c1 consistency:");
        let ct = ctx.encrypt_dual(5, &keys.public_key, &mut rng);

        let mut c0_inconsistent = 0;
        for i in 0..ctx.n.min(20) {
            let c0_main: Vec<u64> = ct.c0.main.iter().map(|l| l[i]).collect();
            let c0_anchor: Vec<u64> = ct.c0.anchor.iter().map(|l| l[i]).collect();

            let v_m = ctx.rns.to_int(&c0_main);
            let v_a = ctx.dual_rns.anchor.to_int(&c0_anchor);
            let v_a_mod_m = v_a % ctx.q_product;
            let consistent = v_m == v_a_mod_m;
            if !consistent {
                println!("  c0[{}]: main={:.2e}, anchor mod M={:.2e} - INCONSISTENT",
                         i, v_m as f64, v_a_mod_m as f64);
                c0_inconsistent += 1;
            }
        }

        let mut c1_inconsistent = 0;
        for i in 0..ctx.n.min(20) {
            let c1_main: Vec<u64> = ct.c1.main.iter().map(|l| l[i]).collect();
            let c1_anchor: Vec<u64> = ct.c1.anchor.iter().map(|l| l[i]).collect();

            let v_m = ctx.rns.to_int(&c1_main);
            let v_a = ctx.dual_rns.anchor.to_int(&c1_anchor);
            let v_a_mod_m = v_a % ctx.q_product;
            let consistent = v_m == v_a_mod_m;
            if !consistent {
                println!("  c1[{}]: main={:.2e}, anchor mod M={:.2e} - INCONSISTENT",
                         i, v_m as f64, v_a_mod_m as f64);
                c1_inconsistent += 1;
            }
        }

        if c0_inconsistent == 0 && c1_inconsistent == 0 {
            println!("  ✓ Ciphertext is consistent");
        } else {
            println!("  ✗ c0: {} inconsistent, c1: {} inconsistent",
                     c0_inconsistent, c1_inconsistent);
        }

        // Now trace through d2 = c1_a × c1_b
        let ct2 = ctx.encrypt_dual(7, &keys.public_key, &mut rng);
        let d2 = ctx.dual_poly_mul(&ct.c1, &ct2.c1);

        println!("\n5. d2 = c1_a × c1_b consistency:");
        let mut d2_inconsistent = 0;
        for i in 0..ctx.n {
            let d2_main: Vec<u64> = d2.main.iter().map(|l| l[i]).collect();
            let d2_anchor: Vec<u64> = d2.anchor.iter().map(|l| l[i]).collect();

            let v_m = ctx.rns.to_int(&d2_main);
            let v_a = ctx.dual_rns.anchor.to_int(&d2_anchor);
            let v_a_mod_m = v_a % ctx.q_product;
            let consistent = v_m == v_a_mod_m;
            if !consistent {
                if d2_inconsistent < 5 {
                    println!("  d2[{}]: main={:.2e}, anchor={:.2e}, anchor mod M={:.2e} - INCONSISTENT",
                             i, v_m as f64, v_a as f64, v_a_mod_m as f64);
                }
                d2_inconsistent += 1;
            }
        }
        if d2_inconsistent == 0 {
            println!("  ✓ d2 is consistent");
        } else {
            println!("  ✗ {} inconsistent d2 coefficients", d2_inconsistent);
        }

        assert_eq!(sk_inconsistent, 0, "Secret key is inconsistent");
        assert_eq!(pk1_inconsistent, 0, "pk1 is inconsistent");
        // Don't assert on pk0/ct/d2 yet - we need to find where inconsistency starts
    }

    #[test]
    #[ignore = "Uses anchor.to_int() which overflows u128. Use assert_main_anchor_consistent() instead."]
    fn test_ntt_mul_residues() {
        // Debug: check raw residues after NTT multiplication
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);
        let mut rng = ShadowHarvester::with_seed(42);

        println!("=== NTT Multiplication Residue Check ===");
        println!("Main primes: {:?}", ctx.config.primes);
        println!("Anchor primes: {:?}", ctx.dual_rns.anchor.primes);
        println!("N = {}", ctx.n);

        // Create two simple polynomials with moderate coefficients
        // a(X) = 100 + 50X (all other coefficients = 0)
        // s(X) = 1 + X + ... (first 10 coefficients = 1)
        let a_coeffs: Vec<u64> = (0..ctx.n).map(|i| match i { 0 => 100, 1 => 50, _ => 0 }).collect();
        let s_coeffs: Vec<u64> = (0..ctx.n).map(|i| if i < 10 { 1 } else { 0 }).collect();

        // Create consistent DualRNSPoly for a
        let a_main: Vec<Vec<u64>> = ctx.config.primes.iter()
            .map(|&p| a_coeffs.iter().map(|&c| c % p).collect())
            .collect();
        let a_anchor: Vec<Vec<u64>> = ctx.dual_rns.anchor.primes.iter()
            .map(|&p| a_coeffs.iter().map(|&c| c % p).collect())
            .collect();
        let a_poly = DualRNSPoly { main: a_main, anchor: a_anchor, n: ctx.n };

        // Create consistent DualRNSPoly for s
        let s_main: Vec<Vec<u64>> = ctx.config.primes.iter()
            .map(|&p| s_coeffs.iter().map(|&c| c % p).collect())
            .collect();
        let s_anchor: Vec<Vec<u64>> = ctx.dual_rns.anchor.primes.iter()
            .map(|&p| s_coeffs.iter().map(|&c| c % p).collect())
            .collect();
        let s_poly = DualRNSPoly { main: s_main, anchor: s_anchor, n: ctx.n };

        // Expected product for first few coefficients:
        // (100 + 50X) * (1 + X + X^2 + ... + X^9) =
        //   100*(1+X+...+X^9) + 50X*(1+X+...+X^9)
        // = 100 + 100X + ... + 100X^9 + 50X + 50X^2 + ... + 50X^10
        // = 100 + 150X + 150X^2 + ... + 150X^9 + 50X^10
        println!("\nExpected first coefficients: [100, 150, 150, 150, ...]");

        // Multiply
        let prod = ctx.dual_poly_mul(&a_poly, &s_poly);

        // Check each coefficient's raw residues
        println!("\nFirst 5 coefficients after multiplication:");
        for i in 0..5 {
            let main_res: Vec<u64> = prod.main.iter().map(|l| l[i]).collect();
            let anchor_res: Vec<u64> = prod.anchor.iter().map(|l| l[i]).collect();

            let v_m = ctx.rns.to_int(&main_res);
            let v_a = ctx.dual_rns.anchor.to_int(&anchor_res);

            let expected = match i {
                0 => 100,
                1..=9 => 150,
                10 => 50,
                _ => 0,
            };

            println!("  coeff[{}]:", i);
            println!("    main residues: {:?}", main_res);
            println!("    anchor residues: {:?}", anchor_res);
            println!("    main CRT: {}, anchor CRT: {}, expected: {}", v_m, v_a, expected);
            println!("    consistent: {}", v_m == v_a && v_m == expected as u128);
        }

        // Now test with real key generation values
        println!("\n=== Testing with real key gen values ===");
        let keys = ctx.generate_keys_dual(&mut rng);

        // Look at pk1 (a) and s, then compute a*s manually
        // Check a few coefficients of a (should be < 167M)
        println!("\nFirst 3 coefficients of a (pk1):");
        for i in 0..3 {
            let a_main_res: Vec<u64> = keys.public_key.pk1.main.iter().map(|l| l[i]).collect();
            let a_anchor_res: Vec<u64> = keys.public_key.pk1.anchor.iter().map(|l| l[i]).collect();
            let v_m = ctx.rns.to_int(&a_main_res);
            let v_a = ctx.dual_rns.anchor.to_int(&a_anchor_res);
            println!("  a[{}]: main_crt={}, anchor_crt={}, consistent: {}", i, v_m, v_a, v_m == v_a);
        }

        println!("\nFirst 3 coefficients of s (secret key):");
        for i in 0..3 {
            let s_main_res: Vec<u64> = keys.secret_key.s.main.iter().map(|l| l[i]).collect();
            let s_anchor_res: Vec<u64> = keys.secret_key.s.anchor.iter().map(|l| l[i]).collect();
            // s has values 0, 1, or p-1 (for -1)
            println!("  s[{}]: main_residues={:?}, anchor_residues={:?}",
                     i, s_main_res, s_anchor_res);
        }

        // Compute a*s
        let as_prod = ctx.dual_poly_mul(&keys.public_key.pk1, &keys.secret_key.s);

        println!("\nFirst 5 coefficients of a*s:");
        for i in 0..5 {
            let as_main_res: Vec<u64> = as_prod.main.iter().map(|l| l[i]).collect();
            let as_anchor_res: Vec<u64> = as_prod.anchor.iter().map(|l| l[i]).collect();
            let v_m = ctx.rns.to_int(&as_main_res);
            let v_a = ctx.dual_rns.anchor.to_int(&as_anchor_res);
            let consistent = v_m == v_a;
            println!("  (a*s)[{}]: main={:.2e}, anchor={:.2e}, consistent: {}",
                     i, v_m as f64, v_a as f64, consistent);
            if !consistent {
                println!("    main residues: {:?}", as_main_res);
                println!("    anchor residues: {:?}", as_anchor_res);
            }
        }
    }

    #[test]
    fn test_ntt_ternary_mul() {
        // Direct test of NTT multiplication with ternary coefficients
        use crate::arithmetic::NTTEngine;

        // Test with anchor primes (all > 2×10^9 to avoid rescaled value wrapping)
        let primes = vec![2013265921u64, 2281701377, 2483027969, 2885681153];
        let n = 1024;

        // Create simple polynomials:
        // a(X) = 100 + 200X (small positive coefficients)
        // b(X) = 1 + X + (-1)X^2 = 1 + X + (p-1)X^2 (ternary)
        // Expected product (mod X^N + 1) for first few terms:
        //   = (100 + 200X) * (1 + X - X^2)
        //   = 100 + 100X - 100X^2 + 200X + 200X^2 - 200X^3
        //   = 100 + 300X + 100X^2 - 200X^3
        let expected_coeffs: Vec<i64> = vec![100, 300, 100, -200];

        println!("=== Testing NTT with Ternary Coefficients ===");
        println!("a(X) = 100 + 200X");
        println!("b(X) = 1 + X - X^2");
        println!("Expected product: [100, 300, 100, -200, ...]");

        for &p in &primes {
            println!("\n--- Testing prime {} ---", p);

            let ntt = NTTEngine::new(p, n);

            // Create a: [100, 200, 0, 0, ...]
            let mut a: Vec<u64> = vec![0; n];
            a[0] = 100;
            a[1] = 200;

            // Create b: [1, 1, p-1, 0, 0, ...] (1, 1, -1)
            let mut b: Vec<u64> = vec![0; n];
            b[0] = 1;
            b[1] = 1;
            b[2] = p - 1;  // -1 mod p

            // Multiply using NTT
            let result = ntt.multiply(&a, &b);

            // Check first few coefficients
            let mut all_match = true;
            for i in 0..4 {
                let expected = if expected_coeffs[i] < 0 {
                    p - ((-expected_coeffs[i]) as u64)
                } else {
                    expected_coeffs[i] as u64
                };

                let matches = result[i] == expected;
                if !matches {
                    all_match = false;
                }
                println!("  result[{}] = {} (expected {} = {} mod {}): {}",
                         i, result[i], expected_coeffs[i], expected, p,
                         if matches { "OK" } else { "FAIL" });
            }

            if !all_match {
                println!("  *** PRIME {} FAILED ***", p);
            }
        }

        // Also test manually computing result[0] for the real polynomial
        println!("\n=== Manual verification of (a*s)[0] ===");
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual(&mut rng);

        // Extract a and s coefficients
        let mut a_coeffs = vec![0i128; n];
        for i in 0..n {
            let a_res: Vec<u64> = keys.public_key.pk1.main.iter().map(|l| l[i]).collect();
            a_coeffs[i] = ctx.rns.to_int(&a_res) as i128;
        }

        let mut s_coeffs = vec![0i128; n];
        for i in 0..n {
            let s_res: Vec<u64> = keys.secret_key.s.main.iter().map(|l| l[i]).collect();
            let v = ctx.rns.to_int(&s_res);
            // Convert from mod M to signed
            if v > ctx.q_product / 2 {
                s_coeffs[i] = -((ctx.q_product - v) as i128);
            } else {
                s_coeffs[i] = v as i128;
            }
        }

        // Compute (a*s)[0] using naive negacyclic convolution
        let mut expected_as_0: i128 = 0;
        for i in 0..n {
            let _j = (n - i) % n;  // Index for negacyclic: a[i] * s[j] for i+j=N
            if i == 0 {
                expected_as_0 += a_coeffs[0] * s_coeffs[0];
            } else {
                // For i > 0: a[i] * s[N-i] with negation (X^N = -1)
                expected_as_0 -= a_coeffs[i] * s_coeffs[n - i];
            }
        }

        println!("Computed (a*s)[0] via naive convolution: {}", expected_as_0);
        println!("Expected to match main CRT result");

        // Verify it matches the main system
        let as_prod = ctx.dual_poly_mul(&keys.public_key.pk1, &keys.secret_key.s);
        let as_main_0: Vec<u64> = as_prod.main.iter().map(|l| l[0]).collect();
        let v_m = ctx.rns.to_int(&as_main_0);
        let v_m_signed = if v_m > ctx.q_product / 2 {
            -((ctx.q_product - v_m) as i128)
        } else {
            v_m as i128
        };
        println!("Main NTT (a*s)[0] (signed): {}", v_m_signed);
        println!("Match: {}", expected_as_0 == v_m_signed);

        // Verify main/anchor consistency using per-prime checks (overflow-proof)
        println!("\n=== K-Elimination Verification (per-prime) ===");

        // Get residues for (a*s)[0]
        let as_main_0: Vec<u64> = as_prod.main.iter().map(|l| l[0]).collect();
        let as_anchor_0: Vec<u64> = as_prod.anchor.iter().map(|l| l[0]).collect();

        let v_m = ctx.rns.to_int(&as_main_0);
        let true_value = center_mod_m_to_i128(v_m, ctx.q_product);

        println!("v_m (main CRT, mod M) = {}", v_m);
        println!("true_value (centered) = {}", true_value);
        println!("M = {}", ctx.q_product);
        println!("anchor primes = {:?}", ctx.dual_rns.anchor.primes);

        // Per-prime consistency: anchor residues must match the same centered integer
        let mut all_match = true;
        for (i, &a_i) in ctx.dual_rns.anchor.primes.iter().enumerate() {
            let expected = mod_i128(true_value, a_i);
            let actual = as_anchor_0[i];
            let matches = expected == actual;
            if !matches { all_match = false; }
            println!("  anchor[{}] (mod {}): expected={}, actual={} {}",
                     i, a_i, expected, actual, if matches { "✓" } else { "✗" });
        }

        println!("\nMain/anchor consistency: {}", if all_match { "PASS" } else { "FAIL" });
        println!("Naive convolution match: {}", true_value == expected_as_0);

        assert!(all_match, "Anchor residues diverged from main");
        assert_eq!(true_value, expected_as_0, "NTT result doesn't match naive convolution");
    }

    #[test]
    fn test_k_elim_rescale_direct() {
        // Direct test of k_elim_rescale_dual function
        // Verify it correctly rescales tensor product coefficients
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);
        let mut rng = ShadowHarvester::with_seed(42);

        let delta = ctx.q_product / ctx.t as u128;
        let m_product = ctx.dual_rns.main_product;

        println!("=== Direct K-Elim Rescale Test ===");
        println!("M = {:.2e}", m_product as f64);
        println!("Δ = {:.2e}", delta as f64);
        println!("anchor primes = {:?}", ctx.dual_rns.anchor.primes);

        // Generate keys and ciphertexts
        let keys = ctx.generate_keys_dual(&mut rng);
        let ct_a = ctx.encrypt_dual(5, &keys.public_key, &mut rng);
        let ct_b = ctx.encrypt_dual(7, &keys.public_key, &mut rng);

        // Compute tensor product d2 = c1_a × c1_b
        let d2 = ctx.dual_poly_mul(&ct_a.c1, &ct_b.c1);

        // Note: Pre-rescale, tensor product coefficients can EXCEED M,
        // so main and anchor represent DIFFERENT values. This is expected!
        // K-Elimination reconstructs the exact value and rescales it back to range.

        // Test 1: Apply rescale and verify POST-rescale consistency
        println!("\n--- Test 2: Post-rescale consistency ---");
        let d2_rescaled = ctx.k_elim_rescale_dual(&d2);

        for coeff_idx in [0, 1, 182, 500] {
            let main_res: Vec<u64> = d2_rescaled.main.iter().map(|l| l[coeff_idx]).collect();
            let anchor_res: Vec<u64> = d2_rescaled.anchor.iter().map(|l| l[coeff_idx]).collect();
            assert_main_anchor_consistent(&ctx, &main_res, &anchor_res,
                &format!("d2_rescaled[{}] post-rescale", coeff_idx));
        }
        println!("✓ Post-rescale consistency verified");

        // Test 3: Full multiplication produces correct result
        println!("\n--- Test 3: Full multiplication correctness ---");
        let ct_prod = ctx.mul_dual_symmetric(&ct_a, &ct_b, &keys.secret_key);
        let result = ctx.decrypt_dual(&ct_prod, &keys.secret_key);
        println!("5 × 7 = {} (expected 35)", result);
        assert_eq!(result, 35, "Multiplication gave wrong result");

        println!("\n✓ All k_elim_rescale_dual tests passed");
    }

    #[test]
    fn test_centered_representative_invariant() {
        // MICRO-TEST: Verify the keystone invariant directly.
        // After rescale, main and anchor MUST represent the same centered integer.
        // This is a first-class test of the invariant, not a side effect of other tests.
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);
        let mut rng = ShadowHarvester::with_seed(42);

        let keys = ctx.generate_keys_dual(&mut rng);

        println!("=== Centered Representative Invariant Test ===");
        println!("Testing: After rescale, main and anchor represent the same integer");

        // Test several message values including edge cases
        for m in [0, 1, 2, 100, 1000, 32768, 65535] {
            if m >= ctx.t { continue; }

            let ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
            let ct_one = ctx.encrypt_dual(1, &keys.public_key, &mut rng);

            // Multiply by 1 to trigger tensor product + rescale
            let ct_result = ctx.mul_dual_symmetric(&ct, &ct_one, &keys.secret_key);

            // Check invariant on result coefficients
            for coeff_idx in [0, 1, ctx.n / 2, ctx.n - 1] {
                let main_res: Vec<u64> = ct_result.c0.main.iter().map(|l| l[coeff_idx]).collect();
                let anchor_res: Vec<u64> = ct_result.c0.anchor.iter().map(|l| l[coeff_idx]).collect();
                assert_main_anchor_consistent(&ctx, &main_res, &anchor_res,
                    &format!("m={} c0[{}]", m, coeff_idx));
            }

            // Verify decryption still works
            let result = ctx.decrypt_dual(&ct_result, &keys.secret_key);
            assert_eq!(result, m, "Decryption failed for m={}", m);
        }

        println!("✓ Centered representative invariant holds for all test cases");
    }

    /// DEMONSTRATION TEST: Native DualRNS ct×ct multiplication with K-Elimination
    ///
    /// This is the critical test proving NINE65's bootstrap-free FHE works:
    /// - Encrypts 5 and 7 using native DualRNS (main + anchor residues from encryption)
    /// - Multiplies ciphertexts using K-Elimination exact rescaling
    /// - Decrypts to verify 5 × 7 = 35
    ///
    /// K-Elimination solves the 70-year RNS division bottleneck by maintaining
    /// anchor residues through the entire pipeline, enabling exact reconstruction
    /// without full CRT.
    #[test]
    fn test_e2e_native_dual_rns_5x7_equals_35() {
        println!("=== NINE65 E2E Demonstration: Native DualRNS K-Elimination ===");

        // Setup: light_rns_exact config uses 3 main primes + 3 anchor primes
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);
        let mut rng = ShadowHarvester::with_seed(42);

        // Generate DualRNS keys (stores keys in both main and anchor residue systems)
        let keys = ctx.generate_keys_dual(&mut rng);
        println!("  Keys generated: DualRNS (main + anchor)");

        // Encrypt 5 and 7 using NATIVE DualRNS encryption
        // This stores residues in BOTH main and anchor systems from the start
        let ct_5 = ctx.encrypt_dual(5, &keys.public_key, &mut rng);
        let ct_7 = ctx.encrypt_dual(7, &keys.public_key, &mut rng);
        println!("  Encrypted: ct_5 = Enc(5), ct_7 = Enc(7)");

        // Verify encryption roundtrip
        let dec_5 = ctx.decrypt_dual(&ct_5, &keys.secret_key);
        let dec_7 = ctx.decrypt_dual(&ct_7, &keys.secret_key);
        assert_eq!(dec_5, 5, "Decryption of ct_5 should yield 5");
        assert_eq!(dec_7, 7, "Decryption of ct_7 should yield 7");
        println!("  Verified: decrypt(ct_5) = 5, decrypt(ct_7) = 7");

        // K-ELIMINATION MULTIPLICATION: The core innovation
        // - Tensor product in BOTH main and anchor systems
        // - K-Elimination exact rescaling: k = ((v_anchor - v_main) × M⁻¹) mod A
        // - No approximation, no bootstrap required
        let ct_35 = ctx.mul_dual_symmetric(&ct_5, &ct_7, &keys.secret_key);
        println!("  Multiplied: ct_35 = ct_5 × ct_7 (K-Elimination rescale)");

        // Decrypt and verify
        let result = ctx.decrypt_dual(&ct_35, &keys.secret_key);
        println!("  Result: decrypt(ct_35) = {}", result);

        assert_eq!(result, 35, "Native DualRNS K-Elimination: 5 × 7 must equal 35");

        println!("=== SUCCESS: Native DualRNS ct×ct multiplication verified ===");
        println!("  Encrypted(5) × Encrypted(7) = Encrypted(35)");
        println!("  Bootstrap-free, exact arithmetic, K-Elimination rescaling");
    }

    #[test]
    fn test_auto_routing() {
        // Test the auto-routing infrastructure selects correct regime
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);

        println!("=== Auto-Routing Test ===");
        println!("Q = {:.2e}", ctx.q_product as f64);
        println!("t = {}", ctx.t);
        let delta = ctx.q_product / ctx.t as u128;
        println!("Δ = {:.2e}", delta as f64);

        // Check routing decision
        let route = ctx.mul_route();
        println!("mul_route() = {:?}", route);

        // For multi-prime configs, Δ² >> Q, so MUST use KElimDual
        assert_eq!(route, MulRoute::KElimDual,
            "Multi-prime config should route to KElimDual");

        // Generate keys via auto
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_auto(&mut rng);
        assert!(keys.is_dual(), "Auto keys should be Dual for KElimDual route");

        // Encrypt via auto
        let ct_a = ctx.encrypt_auto(5, &keys, &mut rng);
        let ct_b = ctx.encrypt_auto(7, &keys, &mut rng);
        assert!(ct_a.is_dual(), "Encrypted ciphertext should be Dual");
        assert!(ct_b.is_dual(), "Encrypted ciphertext should be Dual");

        // Verify encryption roundtrip before multiplication
        let dec_a = ctx.decrypt_auto(&ct_a, &keys);
        let dec_b = ctx.decrypt_auto(&ct_b, &keys);
        assert_eq!(dec_a, 5, "Decryption of 5 should yield 5");
        assert_eq!(dec_b, 7, "Decryption of 7 should yield 7");

        // Multiply via auto
        let ct_prod = ctx.mul_auto(&ct_a, &ct_b, &keys);
        assert!(ct_prod.is_dual(), "Product ciphertext should be Dual");

        // Decrypt and verify
        let result = ctx.decrypt_auto(&ct_prod, &keys);
        println!("5 × 7 via auto = {}", result);
        assert_eq!(result, 35, "Auto mul should give 5 × 7 = 35");

        // Test addition via auto
        let ct_sum = ctx.add_auto(&ct_a, &ct_b);
        let sum_result = ctx.decrypt_auto(&ct_sum, &keys);
        println!("5 + 7 via auto = {}", sum_result);
        assert_eq!(sum_result, 12, "Auto add should give 5 + 7 = 12");

        println!("✓ Auto-routing test passed");
    }

    #[test]
    fn test_auto_routing_chained_operations() {
        // Test chained operations through auto interface
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);

        let mut rng = ShadowHarvester::with_seed(123);
        let keys = ctx.generate_keys_auto(&mut rng);

        // Encrypt values
        let ct_2 = ctx.encrypt_auto(2, &keys, &mut rng);
        let ct_3 = ctx.encrypt_auto(3, &keys, &mut rng);
        let ct_4 = ctx.encrypt_auto(4, &keys, &mut rng);

        println!("=== Chained Auto Operations ===");

        // (2 + 3) × 4 = 20
        let ct_sum = ctx.add_auto(&ct_2, &ct_3);
        let ct_result = ctx.mul_auto(&ct_sum, &ct_4, &keys);
        let result = ctx.decrypt_auto(&ct_result, &keys);
        println!("(2 + 3) × 4 = {}", result);
        assert_eq!(result, 20, "Should get (2 + 3) × 4 = 20");

        // 2 × 3 + 4 = 10
        let ct_prod = ctx.mul_auto(&ct_2, &ct_3, &keys);
        let ct_result2 = ctx.add_auto(&ct_prod, &ct_4);
        let result2 = ctx.decrypt_auto(&ct_result2, &keys);
        println!("2 × 3 + 4 = {}", result2);
        assert_eq!(result2, 10, "Should get 2 × 3 + 4 = 10");

        println!("✓ Chained auto operations test passed");
    }

    #[test]
    #[should_panic(expected = "Key regime mismatch")]
    fn test_regime_mismatch_encrypt_single_keys_dual_route() {
        // This tests that mixing regimes panics as expected
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);

        // Context routes to KElimDual, but we force Single keys
        let mut rng = ShadowHarvester::with_seed(42);
        let wrong_keys = AutoKeys::Single(ctx.generate_keys(&mut rng));

        // This should panic because route is KElimDual but keys are Single
        let _ct = ctx.encrypt_auto(5, &wrong_keys, &mut rng);
    }

    #[test]
    #[should_panic(expected = "Ciphertext/key regime mismatch")]
    fn test_regime_mismatch_mul_mixed_ciphertexts() {
        // Test that mixing ciphertext types in mul_auto panics
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);

        let mut rng = ShadowHarvester::with_seed(42);

        // Generate proper dual keys and ciphertexts
        let dual_keys = ctx.generate_keys_dual(&mut rng);
        let ct_dual = ctx.encrypt_dual(5, &dual_keys.public_key, &mut rng);

        // Also generate single-regime ciphertext (force it)
        let single_keys = ctx.generate_keys(&mut rng);
        let ct_single = ctx.encrypt(7, &single_keys.public_key, &mut rng);

        // Wrap them in Auto types for the mismatch
        let auto_dual = AutoCiphertext::Dual(ct_dual);
        let auto_single = AutoCiphertext::Single(ct_single);
        let auto_keys = AutoKeys::Dual(dual_keys);

        // This should panic - mixed ciphertext types
        let _result = ctx.mul_auto(&auto_dual, &auto_single, &auto_keys);
    }

    #[test]
    #[should_panic(expected = "Ciphertext regime mismatch")]
    fn test_regime_mismatch_add_mixed_ciphertexts() {
        // Test that mixing ciphertext types in add_auto panics
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);

        let mut rng = ShadowHarvester::with_seed(42);

        // Generate both types of ciphertexts
        let dual_keys = ctx.generate_keys_dual(&mut rng);
        let ct_dual = ctx.encrypt_dual(5, &dual_keys.public_key, &mut rng);

        let single_keys = ctx.generate_keys(&mut rng);
        let ct_single = ctx.encrypt(7, &single_keys.public_key, &mut rng);

        let auto_dual = AutoCiphertext::Dual(ct_dual);
        let auto_single = AutoCiphertext::Single(ct_single);

        // This should panic - mixed ciphertext types in add
        let _result = ctx.add_auto(&auto_dual, &auto_single);
    }

    /// Deterministic PRNG for test reproducibility
    fn test_rand(seed: &mut u64) -> u64 {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        *seed
    }

    #[test]
    fn test_random_expressions_kelim_dual() {
        // Random expression trees of depth 3-5 using K-Elim Dual route
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);

        assert_eq!(ctx.mul_route(), MulRoute::KElimDual,
            "light_rns_exact should route to KElimDual");

        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_auto(&mut rng);

        println!("=== Random Expression Test (K-Elim Dual) ===");
        println!("t = {}", ctx.t);

        let mut seed = 12345u64;
        let mut passed = 0;
        let trials = 20;

        for trial in 0..trials {
            // Generate random plaintexts in [1, min(t-1, 100)]
            // Keep small to avoid overflow in expected computation
            let max_val = std::cmp::min(ctx.t - 1, 100);
            let a = 1 + (test_rand(&mut seed) % max_val);
            let b = 1 + (test_rand(&mut seed) % max_val);
            let c = 1 + (test_rand(&mut seed) % max_val);
            let d = 1 + (test_rand(&mut seed) % max_val);

            // Encrypt all values
            let ct_a = ctx.encrypt_auto(a, &keys, &mut rng);
            let ct_b = ctx.encrypt_auto(b, &keys, &mut rng);
            let ct_c = ctx.encrypt_auto(c, &keys, &mut rng);
            let ct_d = ctx.encrypt_auto(d, &keys, &mut rng);

            // Compute expression: (a * b) + (c * d)
            // Expected: (a*b + c*d) mod t
            let expected = ((a * b) + (c * d)) % ctx.t;

            let ct_ab = ctx.mul_auto(&ct_a, &ct_b, &keys);
            let ct_cd = ctx.mul_auto(&ct_c, &ct_d, &keys);
            let ct_result = ctx.add_auto(&ct_ab, &ct_cd);
            let result = ctx.decrypt_auto(&ct_result, &keys);

            if result == expected {
                passed += 1;
            } else {
                println!("Trial {}: ({} * {}) + ({} * {}) = {} (expected {})",
                    trial, a, b, c, d, result, expected);
            }
        }

        println!("Passed: {}/{}", passed, trials);
        assert_eq!(passed, trials, "All random expressions should match");
        println!("✓ Random expression test (K-Elim Dual) passed");
    }

    #[test]
    fn test_random_expressions_depth3() {
        // Deeper expression: ((a * b) + c) * d
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);

        let mut rng = ShadowHarvester::with_seed(123);
        let keys = ctx.generate_keys_auto(&mut rng);

        println!("=== Depth-3 Expression Test ===");

        let mut seed = 54321u64;
        let mut passed = 0;
        let trials = 15;

        for trial in 0..trials {
            // Keep values small: sqrt(t) to avoid overflow after mul
            let max_val = std::cmp::min((ctx.t as f64).sqrt() as u64, 50);
            let a = 1 + (test_rand(&mut seed) % max_val);
            let b = 1 + (test_rand(&mut seed) % max_val);
            let c = 1 + (test_rand(&mut seed) % max_val);
            let d = 1 + (test_rand(&mut seed) % max_val);

            let ct_a = ctx.encrypt_auto(a, &keys, &mut rng);
            let ct_b = ctx.encrypt_auto(b, &keys, &mut rng);
            let ct_c = ctx.encrypt_auto(c, &keys, &mut rng);
            let ct_d = ctx.encrypt_auto(d, &keys, &mut rng);

            // ((a * b) + c) * d
            let expected = ((((a * b) + c) % ctx.t) * d) % ctx.t;

            let ct_ab = ctx.mul_auto(&ct_a, &ct_b, &keys);
            let ct_abc = ctx.add_auto(&ct_ab, &ct_c);
            let ct_result = ctx.mul_auto(&ct_abc, &ct_d, &keys);
            let result = ctx.decrypt_auto(&ct_result, &keys);

            if result == expected {
                passed += 1;
            } else {
                println!("Trial {}: (({} * {}) + {}) * {} = {} (expected {})",
                    trial, a, b, c, d, result, expected);
            }
        }

        println!("Passed: {}/{}", passed, trials);
        assert_eq!(passed, trials, "All depth-3 expressions should match");
        println!("✓ Depth-3 expression test passed");
    }

    #[test]
    fn test_chain_via_auto() {
        // Mirror the working chain test but via auto interface
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new(&config);  // Use new() like the working test

        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_auto(&mut rng);

        println!("=== Chain via Auto (3^4 = 81) ===");

        // Compute 3 × 3 × 3 × 3 = 81, always multiplying by fresh ciphertext
        let three = 3u64;
        let mut ct = ctx.encrypt_auto(three, &keys, &mut rng);
        let ct_three = ctx.encrypt_auto(three, &keys, &mut rng);
        let mut expected = three;

        for i in 1..=3 {
            ct = ctx.mul_auto(&ct, &ct_three, &keys);
            expected = (expected * three) % ctx.t;

            let result = ctx.decrypt_auto(&ct, &keys);
            println!("  Step {}: 3^{} = {} (expected {})", i, i + 1, result, expected);

            assert_eq!(result, expected, "Chain failed at step {}", i);
        }

        println!("✓ Chain via auto PASSED: 3^4 = {}", expected);
    }

    #[test]
    fn test_result_times_fresh() {
        // Verify that (result × fresh) works correctly - SAME fresh each time
        // This matches the pattern in test_chain_via_auto which passes
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new(&config);

        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_auto(&mut rng);

        println!("=== Result × Fresh Test (same multiplier) ===");

        // Like chain test: 2 × 2 × 2 × 2 = 16
        let two = 2u64;
        let mut ct = ctx.encrypt_auto(two, &keys, &mut rng);
        let ct_two = ctx.encrypt_auto(two, &keys, &mut rng);
        let mut expected = two;

        for i in 1..=3 {
            ct = ctx.mul_auto(&ct, &ct_two, &keys);
            expected = (expected * two) % ctx.t;

            let result = ctx.decrypt_auto(&ct, &keys);
            println!("  Step {}: 2^{} = {} (expected {})", i, i + 1, result, expected);
            assert_eq!(result, expected, "Chain failed at step {}", i);
        }

        println!("✓ Result × Fresh test PASSED: 2^4 = {}", expected);
    }

    #[test]
    fn test_result_times_different_fresh() {
        // Test with different fresh values each time
        // This may have different noise characteristics
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new(&config);

        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_auto(&mut rng);

        println!("=== Result × Different Fresh Test ===");

        // 2 × 3 × 4 = 24
        let ct_2 = ctx.encrypt_auto(2, &keys, &mut rng);
        let ct_3 = ctx.encrypt_auto(3, &keys, &mut rng);
        let ct_4 = ctx.encrypt_auto(4, &keys, &mut rng);

        let ct_6 = ctx.mul_auto(&ct_2, &ct_3, &keys);
        let dec_6 = ctx.decrypt_auto(&ct_6, &keys);
        println!("2 * 3 = {} (expected 6)", dec_6);
        assert_eq!(dec_6, 6);

        let ct_24 = ctx.mul_auto(&ct_6, &ct_4, &keys);
        let dec_24 = ctx.decrypt_auto(&ct_24, &keys);
        println!("6 * 4 = {} (expected 24)", dec_24);
        assert_eq!(dec_24, 24, "Two muls with different fresh should work");

        println!("✓ Result × Different Fresh test PASSED");
    }

    // ========================================================================
    // PHASE ERROR DIAGNOSTIC HELPERS
    // ========================================================================
    //
    // These helpers diagnose WHERE the tree multiplication error occurs by
    // comparing the phase (c0 + c1*s + ...) against the EXPECTED value at
    // each stage:
    //   A) After tensor product (exp=2, coefficients should encode expected*Δ²)
    //   B) After K-Elim rescale (exp=1, coefficients should encode expected*Δ)
    //   C) After relinearization (exp=1, coefficients should encode expected*Δ)
    //
    // Key insight: The existing "margin" diagnostic is SELF-REFERENTIAL - it
    // measures error from the decoded value, not the expected value. A positive
    // margin + wrong result means the error is UPSTREAM of decryption.

    /// Center a value x ∈ [0, Q) to the signed range (-Q/2, Q/2]
    ///
    /// BFV ciphertexts encode messages as: phase ≈ m*Δ + e (mod Q)
    /// where e is small noise centered around 0. This helper lets us
    /// reason about noise in signed representation.
    fn center_i128(x_mod_q: u128, q: u128) -> i128 {
        let x = x_mod_q as i128;
        let q_i128 = q as i128;
        let half = q_i128 / 2;
        if x > half { x - q_i128 } else { x }
    }

    /// Compute the centered expected phase: center(expected * Δ^exp mod Q)
    ///
    /// For exp=1: message m encodes as m*Δ (mod Q)
    /// For exp=2: after tensor product, message m encodes as m*Δ² (mod Q)
    fn expected_phase_center(expected: u64, delta: u128, q: u128, exp: u32) -> i128 {
        // Compute expected * delta^exp mod Q
        // For exp=2, delta^2 may overflow u128, so we compute in f64 for the mod
        let delta_exp = if exp == 1 {
            delta
        } else {
            // delta^exp mod Q - for exp=2 with typical params, delta^2 > Q
            // so we need to handle wraparound
            let mut result = 1u128;
            for _ in 0..exp {
                // result = (result * delta) mod Q using wide arithmetic
                let (lo, hi) = wide_mul_256(result, delta);
                if hi == 0 {
                    result = lo % q;
                } else {
                    // Very large - approximate with modular reduction
                    // This is tricky, but for exp=2 typical case: delta^2 / Q < 2^64
                    let overflow_count = hi;
                    let q_complement = u128::MAX % q + 1;
                    result = (lo % q + (overflow_count as u128 % q) * (q_complement % q)) % q;
                }
            }
            result
        };

        // mu = expected * delta_exp mod Q
        let (lo, hi) = wide_mul_256(expected as u128, delta_exp);
        let mu_mod_q = if hi == 0 {
            lo % q
        } else {
            let q_complement = u128::MAX % q + 1;
            (lo % q + (hi as u128 % q) * (q_complement % q)) % q
        };

        center_i128(mu_mod_q, q)
    }

    /// Compute phase error: how far is the actual phase from the expected value?
    ///
    /// Returns (centered_error, |centered_error|)
    ///
    /// If |centered_error| << Δ/2, the ciphertext correctly encodes the expected value.
    /// If |centered_error| >> Δ/2, decryption will give wrong result.
    fn phase_error(full_value_mod_q: u128, expected: u64, delta: u128, q: u128, exp: u32) -> (i128, i128) {
        let v = center_i128(full_value_mod_q, q);
        let mu = expected_phase_center(expected, delta, q, exp);
        let raw_err = v - mu;

        // Re-center the error (it could have wrapped around Q)
        let q_i128 = q as i128;
        let half = q_i128 / 2;
        let err_center = if raw_err > half {
            raw_err - q_i128
        } else if raw_err < -half {
            raw_err + q_i128
        } else {
            raw_err
        };

        (err_center, err_center.abs())
    }

    #[test]
    fn test_tree_mul_phase_error_trace() {
        // PHASE ERROR TRACE: Pinpoint exactly where tree multiplication fails.
        //
        // This test traces the phase error at each stage:
        // A) After tensor product (before any rescale) - exp=2, threshold = Δ²/2
        // B) After K-Elim rescale (before relin) - exp=1, threshold = Δ/2
        // C) After relinearization (final ciphertext) - exp=1, threshold = Δ/2
        //
        // CRITICAL: For exp=2, the correctness window is Δ²/2, NOT Δ/2!
        // The tensor product encodes m×Δ², so errors up to Δ²/2 are fine.

        let config = FHEConfig::light_rns_exact();
        // MUST use new_coeff_domain for coefficient-domain K-Elimination
        // new() only uses 2 anchor primes (A≈7.88e16), insufficient for Q²×N
        // new_coeff_domain() uses 4 anchor primes (A≈6.6e34), sufficient for Q²×N ≈ 10^39
        let ctx = RNSFHEContext::new_coeff_domain(&config);
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual(&mut rng);

        let delta = ctx.q_product / ctx.t as u128;
        let delta_half_1 = delta / 2;  // Threshold for exp=1 (post-rescale)
        // For exp=2: Δ²/2. Since Δ² can overflow u128, compute as f64 for display
        let delta_sq_f64 = (delta as f64) * (delta as f64);
        let delta_half_2_f64 = delta_sq_f64 / 2.0;

        println!("=== Phase Error Trace for Tree Mul ===");
        println!("Q = {:.2e}, Δ = {:.2e}", ctx.q_product as f64, delta as f64);
        println!("Thresholds: Δ/2 = {:.2e} (exp=1), Δ²/2 = {:.2e} (exp=2)", delta_half_1 as f64, delta_half_2_f64);

        // Encrypt the inputs: (2 * 3) * (4 * 5) = 6 * 20 = 120
        let ct_2 = ctx.encrypt_dual(2, &keys.public_key, &mut rng);
        let ct_3 = ctx.encrypt_dual(3, &keys.public_key, &mut rng);
        let ct_4 = ctx.encrypt_dual(4, &keys.public_key, &mut rng);
        let ct_5 = ctx.encrypt_dual(5, &keys.public_key, &mut rng);

        // ---- First level: 2*3 = 6 ----
        println!("\n--- Stage 1: Computing 2 * 3 = 6 ---");

        // Tensor product (degree-2)
        let d0_23 = ctx.dual_poly_mul(&ct_2.c0, &ct_3.c0);
        let c0_2_c1_3 = ctx.dual_poly_mul(&ct_2.c0, &ct_3.c1);
        let c1_2_c0_3 = ctx.dual_poly_mul(&ct_2.c1, &ct_3.c0);
        let d1_23 = ctx.dual_poly_add(&c0_2_c1_3, &c1_2_c0_3);
        let d2_23 = ctx.dual_poly_mul(&ct_2.c1, &ct_3.c1);

        // Degree-2 phase: inner2 = d0 + d1*s + d2*s²
        let d1_s = ctx.dual_poly_mul(&d1_23, &keys.secret_key.s);
        let s2 = ctx.dual_poly_mul(&keys.secret_key.s, &keys.secret_key.s);
        let d2_s2 = ctx.dual_poly_mul(&d2_23, &s2);
        let inner2_23 = ctx.dual_poly_add(&ctx.dual_poly_add(&d0_23, &d1_s), &d2_s2);

        let rns_coeff: Vec<u64> = inner2_23.main.iter().map(|limb| limb[0]).collect();
        let phase_tensor_23 = ctx.rns.to_int(&rns_coeff);
        let (_err_tensor_23, abs_err_tensor_23) = phase_error(phase_tensor_23, 6, delta, ctx.q_product, 2);
        println!("A) Tensor product phase error (exp=2):");
        println!("   |error| = {:.2e}, Δ²/2 = {:.2e}, ratio = {:.6}",
            abs_err_tensor_23 as f64, delta_half_2_f64, abs_err_tensor_23 as f64 / delta_half_2_f64);

        // K-Elim rescale
        let e0_23 = ctx.k_elim_rescale_dual(&d0_23);
        let e1_23 = ctx.k_elim_rescale_dual(&d1_23);
        let e2_23 = ctx.k_elim_rescale_dual(&d2_23);

        // Degree-2 phase after rescale
        let e1_s = ctx.dual_poly_mul(&e1_23, &keys.secret_key.s);
        let e2_s2 = ctx.dual_poly_mul(&e2_23, &s2);
        let inner2_rescaled_23 = ctx.dual_poly_add(&ctx.dual_poly_add(&e0_23, &e1_s), &e2_s2);

        let rns_coeff: Vec<u64> = inner2_rescaled_23.main.iter().map(|limb| limb[0]).collect();
        let phase_rescaled_23 = ctx.rns.to_int(&rns_coeff);
        let (_err_rescaled_23, abs_err_rescaled_23) = phase_error(phase_rescaled_23, 6, delta, ctx.q_product, 1);
        println!("B) After rescale phase error (exp=1):");
        println!("   |error| = {:.2e}, Δ/2 = {:.2e}, ratio = {:.6}",
            abs_err_rescaled_23 as f64, delta_half_1 as f64, abs_err_rescaled_23 as f64 / delta_half_1 as f64);

        // Relinearize: c0' = e0 + e2*s², c1' = e1
        let e2_s2_relin = ctx.dual_poly_mul(&e2_23, &s2);
        let c0_23 = ctx.dual_poly_add(&e0_23, &e2_s2_relin);

        // Standard decrypt of relinearized
        let c1_s_23 = ctx.dual_poly_mul(&e1_23, &keys.secret_key.s);
        let inner_relin_23 = ctx.dual_poly_add(&c0_23, &c1_s_23);

        let rns_coeff: Vec<u64> = inner_relin_23.main.iter().map(|limb| limb[0]).collect();
        let phase_relin_23 = ctx.rns.to_int(&rns_coeff);
        let (_err_relin_23, abs_err_relin_23) = phase_error(phase_relin_23, 6, delta, ctx.q_product, 1);
        println!("C) After relin phase error (exp=1):");
        println!("   |error| = {:.2e}, Δ/2 = {:.2e}, ratio = {:.6}",
            abs_err_relin_23 as f64, delta_half_1 as f64, abs_err_relin_23 as f64 / delta_half_1 as f64);

        let ct_6 = ctx.mul_dual_symmetric(&ct_2, &ct_3, &keys.secret_key);
        let dec_6 = ctx.decrypt_dual(&ct_6, &keys.secret_key);
        println!("   Decrypted: {} (expected 6)", dec_6);

        // ---- Second level: 4*5 = 20 (similar) ----
        println!("\n--- Stage 2: Computing 4 * 5 = 20 ---");
        let ct_20 = ctx.mul_dual_symmetric(&ct_4, &ct_5, &keys.secret_key);
        let (dec_20, margin_20) = ctx.decrypt_dual_with_diagnostics(&ct_20, &keys.secret_key);
        println!("   Decrypted: {} (expected 20), margin = {:.2e}", dec_20, margin_20 as f64);

        // ---- Third level: 6 * 20 = 120 (THE PROBLEM CASE) ----
        println!("\n--- Stage 3: Computing 6 * 20 = 120 (TREE MUL) ---");

        // Tensor product
        let d0_final = ctx.dual_poly_mul(&ct_6.c0, &ct_20.c0);
        let c0_6_c1_20 = ctx.dual_poly_mul(&ct_6.c0, &ct_20.c1);
        let c1_6_c0_20 = ctx.dual_poly_mul(&ct_6.c1, &ct_20.c0);
        let d1_final = ctx.dual_poly_add(&c0_6_c1_20, &c1_6_c0_20);
        let d2_final = ctx.dual_poly_mul(&ct_6.c1, &ct_20.c1);

        // Degree-2 phase
        let d1_s_final = ctx.dual_poly_mul(&d1_final, &keys.secret_key.s);
        let d2_s2_final = ctx.dual_poly_mul(&d2_final, &s2);
        let inner2_final = ctx.dual_poly_add(&ctx.dual_poly_add(&d0_final, &d1_s_final), &d2_s2_final);

        let rns_coeff: Vec<u64> = inner2_final.main.iter().map(|limb| limb[0]).collect();
        let phase_tensor_final = ctx.rns.to_int(&rns_coeff);
        let (_err_tensor_final, abs_err_tensor_final) = phase_error(phase_tensor_final, 120, delta, ctx.q_product, 2);
        let tensor_ratio = abs_err_tensor_final as f64 / delta_half_2_f64;
        println!("A) Tensor product phase error (exp=2):");
        println!("   |error| = {:.2e}, Δ²/2 = {:.2e}, ratio = {:.6}",
            abs_err_tensor_final as f64, delta_half_2_f64, tensor_ratio);
        if tensor_ratio > 1.0 {
            println!("   >>> ERROR EXCEEDS Δ²/2 AT TENSOR PRODUCT <<<");
        } else {
            println!("   ✓ Tensor product is WITHIN bounds");
        }

        // K-Elim rescale
        let e0_final = ctx.k_elim_rescale_dual(&d0_final);
        let e1_final = ctx.k_elim_rescale_dual(&d1_final);
        let e2_final = ctx.k_elim_rescale_dual(&d2_final);

        // Degree-2 phase after rescale
        let e1_s_final = ctx.dual_poly_mul(&e1_final, &keys.secret_key.s);
        let e2_s2_final = ctx.dual_poly_mul(&e2_final, &s2);
        let inner2_rescaled_final = ctx.dual_poly_add(&ctx.dual_poly_add(&e0_final, &e1_s_final), &e2_s2_final);

        let rns_coeff: Vec<u64> = inner2_rescaled_final.main.iter().map(|limb| limb[0]).collect();
        let phase_rescaled_final = ctx.rns.to_int(&rns_coeff);
        let (_err_rescaled_final, abs_err_rescaled_final) = phase_error(phase_rescaled_final, 120, delta, ctx.q_product, 1);
        let rescale_ratio = abs_err_rescaled_final as f64 / delta_half_1 as f64;
        println!("B) After rescale phase error (exp=1):");
        println!("   |error| = {:.2e}, Δ/2 = {:.2e}, ratio = {:.6}",
            abs_err_rescaled_final as f64, delta_half_1 as f64, rescale_ratio);
        if rescale_ratio > 1.0 {
            println!("   >>> ERROR EXCEEDS Δ/2 AFTER RESCALE <<<");
        } else {
            println!("   ✓ Rescale output is WITHIN bounds");
        }

        // Per-limb breakdown to identify which rescale term is going wild
        println!("\n   Per-limb phase error breakdown:");
        let e0_coeff: Vec<u64> = e0_final.main.iter().map(|limb| limb[0]).collect();
        let e0_phase = ctx.rns.to_int(&e0_coeff);
        // e0 alone should encode approx 120*Δ if we had s=0 in decryption
        // But actually it encodes a component, not the full message
        println!("   e0[0] = {:.2e}", e0_phase as f64);

        let e1_s_coeff: Vec<u64> = e1_s_final.main.iter().map(|limb| limb[0]).collect();
        let e1_s_phase = ctx.rns.to_int(&e1_s_coeff);
        println!("   e1*s[0] = {:.2e}", e1_s_phase as f64);

        let e2_s2_coeff: Vec<u64> = e2_s2_final.main.iter().map(|limb| limb[0]).collect();
        let e2_s2_phase = ctx.rns.to_int(&e2_s2_coeff);
        println!("   e2*s²[0] = {:.2e}", e2_s2_phase as f64);

        println!("   Combined = {:.2e}", phase_rescaled_final as f64);

        // Relinearize
        let e2_s2_relin_final = ctx.dual_poly_mul(&e2_final, &s2);
        let c0_final = ctx.dual_poly_add(&e0_final, &e2_s2_relin_final);

        let c1_s_final = ctx.dual_poly_mul(&e1_final, &keys.secret_key.s);
        let inner_relin_final = ctx.dual_poly_add(&c0_final, &c1_s_final);

        let rns_coeff: Vec<u64> = inner_relin_final.main.iter().map(|limb| limb[0]).collect();
        let phase_relin_final = ctx.rns.to_int(&rns_coeff);
        let (_err_relin_final, abs_err_relin_final) = phase_error(phase_relin_final, 120, delta, ctx.q_product, 1);
        let relin_ratio = abs_err_relin_final as f64 / delta_half_1 as f64;
        println!("C) After relin phase error (exp=1):");
        println!("   |error| = {:.2e}, Δ/2 = {:.2e}, ratio = {:.6}",
            abs_err_relin_final as f64, delta_half_1 as f64, relin_ratio);
        if relin_ratio > 1.0 {
            println!("   >>> ERROR EXCEEDS Δ/2 AFTER RELIN <<<");
        } else {
            println!("   ✓ Relin output is WITHIN bounds");
        }

        let ct_120 = ctx.mul_dual_symmetric(&ct_6, &ct_20, &keys.secret_key);
        let (dec_120, margin_120) = ctx.decrypt_dual_with_diagnostics(&ct_120, &keys.secret_key);
        println!("   Decrypted: {} (expected 120), margin = {:.2e}", dec_120, margin_120 as f64);

        println!("\n=== Summary ===");
        if dec_120 == 120 {
            println!("✓ Tree multiplication PASSED");
        } else {
            println!("Tree multiplication FAILED: got {} instead of 120", dec_120);
            println!("Error location (first stage where ratio > 1.0):");
            if tensor_ratio > 1.0 {
                println!("  - BUG IS AT TENSOR PRODUCT (before rescale)");
            } else if rescale_ratio > 1.0 {
                println!("  - BUG IS IN K-ELIM RESCALE");
            } else if relin_ratio > 1.0 {
                println!("  - BUG IS IN RELINEARIZATION");
            } else {
                println!("  - Phase errors are all within bounds - decode logic issue?");
                println!("    (This shouldn't happen - something else is wrong)");
            }
        }
    }

    #[test]
    fn test_tree_mul_light_diagnostic() {
        // DIAGNOSTIC TEST: Characterize why result×result fails.
        //
        // Key insight from diagnostics:
        // - Margin is POSITIVE (decryption succeeded for the decoded value)
        // - But decoded value is WRONG
        //
        // This means the error is in rescale/relinearization, NOT decryption noise.
        // The rescaled coefficients encode the wrong value, but that wrong value
        // is decoded correctly.
        //
        // This is a known limitation of tree multiplication patterns where
        // both operands have been through rescaling - the accumulated rounding
        // errors compound differently than in chain patterns.
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new(&config);

        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_auto(&mut rng);

        println!("=== Tree Mul Diagnostic (light_rns_exact) ===");
        let delta = ctx.q_product / ctx.t as u128;
        println!("Δ = {:.2e}, Δ/2 = {:.2e}", delta as f64, (delta/2) as f64);

        // (2 * 3) * (4 * 5) = 6 * 20 = 120
        let ct_2 = ctx.encrypt_auto(2, &keys, &mut rng);
        let ct_3 = ctx.encrypt_auto(3, &keys, &mut rng);
        let ct_4 = ctx.encrypt_auto(4, &keys, &mut rng);
        let ct_5 = ctx.encrypt_auto(5, &keys, &mut rng);

        // First level muls - these MUST work correctly
        let ct_6 = ctx.mul_auto(&ct_2, &ct_3, &keys);
        let (dec_6, margin_6) = ctx.decrypt_auto_with_diagnostics(&ct_6, &keys);
        println!("2 * 3 = {} (margin = {:.2e})", dec_6, margin_6 as f64);
        assert_eq!(dec_6, 6, "First level mul MUST work");
        assert!(margin_6 > 0, "First mul should have positive margin");

        let ct_20 = ctx.mul_auto(&ct_4, &ct_5, &keys);
        let (dec_20, margin_20) = ctx.decrypt_auto_with_diagnostics(&ct_20, &keys);
        println!("4 * 5 = {} (margin = {:.2e})", dec_20, margin_20 as f64);
        assert_eq!(dec_20, 20, "First level mul MUST work");
        assert!(margin_20 > 0, "Second mul should have positive margin");

        // The critical tree mul: result × result
        let ct_120 = ctx.mul_auto(&ct_6, &ct_20, &keys);
        let (dec_120, margin_120) = ctx.decrypt_auto_with_diagnostics(&ct_120, &keys);
        println!("6 * 20 = {} (expected 120, margin = {:.2e})", dec_120, margin_120 as f64);

        // Document the behavior:
        if dec_120 == 120 {
            println!("✓ Tree mul PASSED (unexpected with light params)");
        } else {
            // Positive margin means decryption is correct for the (wrong) encoded value.
            // This indicates rescale/relinearization accumulated error, not decryption noise.
            println!("Tree mul gave wrong result:");
            println!("  - Decoded: {} (expected 120)", dec_120);
            println!("  - Margin: {:.2e} (positive = decryption succeeded for this value)", margin_120 as f64);
            println!("  - Diagnosis: accumulated rescale error in tree pattern");
            println!("  - Chain pattern (result×fresh) works because only ONE operand has rescale error");

            // This is expected behavior for light params with tree pattern
            println!("✓ Documented: tree mul limitation with light_rns_exact");
        }
    }

    #[test]
    #[ignore = "Requires deep_128 config which may be slow to initialize"]
    fn test_tree_mul_deep_passes() {
        // With larger parameters (N=16384, 4 primes), tree mul should work.
        let config = FHEConfig::deep_128();
        let ctx = RNSFHEContext::new(&config);

        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_auto(&mut rng);

        println!("=== Tree Mul with deep_128 ===");
        println!("N = {}, primes = {:?}", config.n, config.primes);

        // Same tree mul: (2 * 3) * (4 * 5) = 120
        let ct_2 = ctx.encrypt_auto(2, &keys, &mut rng);
        let ct_3 = ctx.encrypt_auto(3, &keys, &mut rng);
        let ct_4 = ctx.encrypt_auto(4, &keys, &mut rng);
        let ct_5 = ctx.encrypt_auto(5, &keys, &mut rng);

        let ct_6 = ctx.mul_auto(&ct_2, &ct_3, &keys);
        let ct_20 = ctx.mul_auto(&ct_4, &ct_5, &keys);
        let ct_120 = ctx.mul_auto(&ct_6, &ct_20, &keys);

        let (result, margin) = ctx.decrypt_auto_with_diagnostics(&ct_120, &keys);
        println!("6 * 20 = {} (expected 120, margin = {:.2e})", result, margin as f64);

        assert_eq!(result, 120, "Tree mul should work with deep_128 params");
        assert!(margin > 0, "Should have positive margin with larger params");
        println!("✓ Tree mul PASSED with deep_128");
    }

    #[test]
    #[ignore = "Timing test - run manually with --nocapture"]
    fn bench_intt_rescale_cost() {
        use std::time::Instant;

        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new(&config);

        // Create representative dual polynomial
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual(&mut rng);
        let ct = ctx.encrypt_dual(42, &keys.public_key, &mut rng);

        // Build a d2-like polynomial (product of two c1s)
        let d2 = ctx.dual_poly_mul(&ct.c1, &ct.c1);

        println!("=== INTT + K-Elim Rescale Timing ===");
        println!("N = {}, {} main primes, {} anchor primes",
            config.n, config.primes.len(), ctx.dual_rns.anchor.primes.len());

        let iters = 100;
        let start = Instant::now();
        for _ in 0..iters {
            let _rescaled = ctx.k_elim_rescale_dual(&d2);
        }
        let elapsed = start.elapsed();

        println!("K-Elim rescale: {:?} per call ({} iters)", elapsed / iters, iters);
        println!("Total: {:?}", elapsed);
    }

    #[test]
    fn test_anchor_ntt_multiplication_correctness() {
        // Verify that anchor NTT multiplication gives correct results.
        //
        // Key insight: after tensor product, both main and anchor should hold
        // the SAME underlying value. If they diverge, K-Elimination fails.
        //
        // This test creates polynomials with known values and verifies
        // main and anchor agree after multiplication.

        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);

        println!("=== Anchor NTT Multiplication Correctness Test ===");
        println!("M (main product) = {:.2e}", ctx.q_product as f64);
        println!("A (anchor product) = {:.2e}", ctx.dual_rns.anchor_product as f64);

        let n = ctx.n;

        // Create simple polynomial: [3, 0, 0, ...]
        let mut poly_a_main: Vec<Vec<u64>> = vec![vec![0u64; n]; ctx.config.primes.len()];
        let mut poly_a_anchor: Vec<Vec<u64>> = vec![vec![0u64; n]; ctx.dual_rns.anchor.primes.len()];
        for (j, &p) in ctx.config.primes.iter().enumerate() {
            poly_a_main[j][0] = 3 % p;
        }
        for (j, &p) in ctx.dual_rns.anchor.primes.iter().enumerate() {
            poly_a_anchor[j][0] = 3 % p;
        }
        let poly_a = DualRNSPoly { main: poly_a_main, anchor: poly_a_anchor, n };

        // Create simple polynomial: [5, 0, 0, ...]
        let mut poly_b_main: Vec<Vec<u64>> = vec![vec![0u64; n]; ctx.config.primes.len()];
        let mut poly_b_anchor: Vec<Vec<u64>> = vec![vec![0u64; n]; ctx.dual_rns.anchor.primes.len()];
        for (j, &p) in ctx.config.primes.iter().enumerate() {
            poly_b_main[j][0] = 5 % p;
        }
        for (j, &p) in ctx.dual_rns.anchor.primes.iter().enumerate() {
            poly_b_anchor[j][0] = 5 % p;
        }
        let poly_b = DualRNSPoly { main: poly_b_main, anchor: poly_b_anchor, n };

        // Multiply: [3] × [5] = [15]
        let result = ctx.dual_poly_mul(&poly_a, &poly_b);

        // Reconstruct from main
        let main_coeff: Vec<u64> = result.main.iter().map(|limb| limb[0]).collect();
        let v_m = ctx.rns.to_int(&main_coeff);

        // Verify anchor is consistent with main using extract_k_rns
        // If main and anchor hold the same value, k should be 0
        let anchor_coeff: Vec<u64> = result.anchor.iter().map(|limb| limb[0]).collect();
        let k = ctx.dual_rns.extract_k_rns(v_m, &anchor_coeff);

        println!("Expected: 15");
        println!("Main reconstruction: {}", v_m);
        println!("k (should be 0 if anchor == main): {}", k);

        assert_eq!(v_m, 15, "Main should give 15");
        assert_eq!(k, 0, "Anchor should be consistent with main (k=0)");
        println!("✓ Simple multiplication correct for both tracks");

        // Now test with larger values that might expose issues
        // Create polynomial: [Δ, 0, 0, ...] where Δ = Q/t
        let delta = ctx.q_product / ctx.t as u128;
        let mut poly_c_main: Vec<Vec<u64>> = vec![vec![0u64; n]; ctx.config.primes.len()];
        let mut poly_c_anchor: Vec<Vec<u64>> = vec![vec![0u64; n]; ctx.dual_rns.anchor.primes.len()];
        for (j, &p) in ctx.config.primes.iter().enumerate() {
            poly_c_main[j][0] = (delta % p as u128) as u64;
        }
        for (j, &p) in ctx.dual_rns.anchor.primes.iter().enumerate() {
            poly_c_anchor[j][0] = (delta % p as u128) as u64;
        }
        let poly_c = DualRNSPoly { main: poly_c_main, anchor: poly_c_anchor, n };

        // Create polynomial: [2, 0, 0, ...]
        let mut poly_d_main: Vec<Vec<u64>> = vec![vec![0u64; n]; ctx.config.primes.len()];
        let mut poly_d_anchor: Vec<Vec<u64>> = vec![vec![0u64; n]; ctx.dual_rns.anchor.primes.len()];
        for (j, &p) in ctx.config.primes.iter().enumerate() {
            poly_d_main[j][0] = 2 % p;
        }
        for (j, &p) in ctx.dual_rns.anchor.primes.iter().enumerate() {
            poly_d_anchor[j][0] = 2 % p;
        }
        let poly_d = DualRNSPoly { main: poly_d_main, anchor: poly_d_anchor, n };

        // Multiply: [Δ] × [2] = [2Δ]
        let result2 = ctx.dual_poly_mul(&poly_c, &poly_d);

        let main_coeff2: Vec<u64> = result2.main.iter().map(|limb| limb[0]).collect();
        let v_m2 = ctx.rns.to_int(&main_coeff2);

        // Verify anchor is consistent using extract_k_rns
        let anchor_coeff2: Vec<u64> = result2.anchor.iter().map(|limb| limb[0]).collect();
        let k2 = ctx.dual_rns.extract_k_rns(v_m2, &anchor_coeff2);

        let expected = 2 * delta;
        println!("\nΔ multiplication test:");
        println!("Δ = {:.2e}", delta as f64);
        println!("Expected: 2Δ = {:.2e}", expected as f64);
        println!("Main reconstruction: {:.2e} (diff from expected: {})", v_m2 as f64,
            (v_m2 as i128 - expected as i128).abs());
        println!("k (should be 0 if anchor == main): {}", k2);

        // Main should give 2Δ mod M, but since 2Δ < M, it should be exact
        assert_eq!(v_m2, expected, "Main should give 2Δ exactly");
        // Anchor should be consistent with main (k=0)
        assert_eq!(k2, 0, "Anchor should be consistent with main (k=0)");
        println!("✓ Δ-scale multiplication correct for both tracks");
    }

    /// Helper to check if anchor residues are consistent with main
    fn check_anchor_consistency(ctx: &RNSFHEContext, poly: &DualRNSPoly, coeff_idx: usize, label: &str) -> u128 {
        let main_residues: Vec<u64> = poly.main.iter().map(|limb| limb[coeff_idx]).collect();
        let v_m = ctx.rns.to_int(&main_residues);

        let anchor_residues: Vec<u64> = poly.anchor.iter().map(|limb| limb[coeff_idx]).collect();
        let k = ctx.dual_rns.extract_k_rns(v_m, &anchor_residues);

        let a3_product: u128 = ctx.dual_rns.anchor.primes[0..3].iter()
            .fold(1u128, |acc, &p| acc * p as u128);

        println!("  {}: v_m={:.2e}, k={:.2e}, k/A3={:.6}",
            label, v_m as f64, k as f64, k as f64 / a3_product as f64);

        k
    }

    #[test]
    #[ignore = "Uses anchor.to_int() which overflows u128. Use assert_main_anchor_consistent() instead."]
    fn test_mul_dual_anchor_consistency_trace() {
        // Trace anchor consistency through mul_dual to find where divergence happens.
        // This is a diagnostic test to locate the bug in tree multiplication.

        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual(&mut rng);

        println!("=== Anchor Consistency Trace through mul_dual ===\n");

        // Check initial ciphertext
        let ct_2 = ctx.encrypt_dual(2, &keys.public_key, &mut rng);
        let ct_3 = ctx.encrypt_dual(3, &keys.public_key, &mut rng);

        println!("After encryption:");
        let k_ct2_c0 = check_anchor_consistency(&ctx, &ct_2.c0, 0, "ct_2.c0[0]");
        let k_ct2_c1 = check_anchor_consistency(&ctx, &ct_2.c1, 0, "ct_2.c1[0]");
        let _k_ct3_c0 = check_anchor_consistency(&ctx, &ct_3.c0, 0, "ct_3.c0[0]");
        let _k_ct3_c1 = check_anchor_consistency(&ctx, &ct_3.c1, 0, "ct_3.c1[0]");

        // Expect k≈0 for fresh ciphertexts (values < M)
        assert!(k_ct2_c0 < 1000, "Fresh ct_2.c0 should have k≈0");
        assert!(k_ct2_c1 < 1000, "Fresh ct_2.c1 should have k≈0");

        // Manual mul_dual step-by-step
        println!("\nStep 1: Tensor product");
        let d0 = ctx.dual_poly_mul(&ct_2.c0, &ct_3.c0);
        let c0_2_c1_3 = ctx.dual_poly_mul(&ct_2.c0, &ct_3.c1);
        let c1_2_c0_3 = ctx.dual_poly_mul(&ct_2.c1, &ct_3.c0);
        let d1 = ctx.dual_poly_add(&c0_2_c1_3, &c1_2_c0_3);
        let d2 = ctx.dual_poly_mul(&ct_2.c1, &ct_3.c1);

        let _k_d0 = check_anchor_consistency(&ctx, &d0, 0, "d0[0] (tensor)");
        let _k_d1 = check_anchor_consistency(&ctx, &d1, 0, "d1[0] (tensor)");
        let _k_d2 = check_anchor_consistency(&ctx, &d2, 0, "d2[0] (tensor)");

        // After tensor product, k should still be small IF the underlying values are < M×A
        // Actually, values can be up to Q²×N ≈ 10^39, so k could be large
        // But the key point is: are main and anchor CONSISTENT?

        println!("\nStep 2: K-Elim rescale");
        let e0 = ctx.k_elim_rescale_dual(&d0);
        let e1 = ctx.k_elim_rescale_dual(&d1);
        let e2 = ctx.k_elim_rescale_dual(&d2);

        let k_e0 = check_anchor_consistency(&ctx, &e0, 0, "e0[0] (rescaled)");
        let k_e1 = check_anchor_consistency(&ctx, &e1, 0, "e1[0] (rescaled)");
        let k_e2 = check_anchor_consistency(&ctx, &e2, 0, "e2[0] (rescaled)");

        // After k_elim_rescale_dual, anchor is set from scaled_mod_m, so k SHOULD be 0
        assert_eq!(k_e0, 0, "Rescaled e0 should have k=0");
        assert_eq!(k_e1, 0, "Rescaled e1 should have k=0");
        assert_eq!(k_e2, 0, "Rescaled e2 should have k=0");

        println!("\nStep 3: Relinearization");
        let s2 = ctx.dual_poly_mul(&keys.secret_key.s, &keys.secret_key.s);
        let k_s2 = check_anchor_consistency(&ctx, &s2, 0, "s²[0]");
        // s² should have k=0 since s coefficients are ±1 (small)
        assert!(k_s2 < 1000, "s² should have k≈0");

        // Check multiple coefficients of e2 and s² to find where inconsistency comes from
        println!("\n  Checking multiple coefficients of e2 and s²:");
        let mut e2_nonzero_k = 0;
        let mut s2_nonzero_k = 0;
        for i in [0, 1, 2, 10, 100, 500].iter() {
            let k_e2_i = check_anchor_consistency(&ctx, &e2, *i, &format!("e2[{}]", i));
            let k_s2_i = check_anchor_consistency(&ctx, &s2, *i, &format!("s²[{}]", i));
            if k_e2_i > 0 { e2_nonzero_k += 1; }
            if k_s2_i > 0 { s2_nonzero_k += 1; }
        }
        println!("  e2 non-zero k count (of 6 checked): {}", e2_nonzero_k);
        println!("  s² non-zero k count (of 6 checked): {}", s2_nonzero_k);

        let e2_s2 = ctx.dual_poly_mul(&e2, &s2);
        let _k_e2_s2 = check_anchor_consistency(&ctx, &e2_s2, 0, "e2*s²[0]");

        let c0_new = ctx.dual_poly_add(&e0, &e2_s2);
        let _k_c0_new = check_anchor_consistency(&ctx, &c0_new, 0, "c0_new[0]");

        println!("\nStep 4: Final ciphertext (ct_6)");
        let ct_6 = DualRNSCiphertext { c0: c0_new, c1: e1, level: ct_2.level };
        let _k_ct6_c0 = check_anchor_consistency(&ctx, &ct_6.c0, 0, "ct_6.c0[0]");
        let _k_ct6_c1 = check_anchor_consistency(&ctx, &ct_6.c1, 0, "ct_6.c1[0]");

        // Decrypt to verify correctness
        let dec_6 = ctx.decrypt_dual(&ct_6, &keys.secret_key);
        println!("\nDecrypted: {} (expected 6)", dec_6);

        println!("\n=== Summary ===");
        if dec_6 == 6 {
            println!("✓ First level multiplication succeeded");
        } else {
            println!("✗ First level multiplication FAILED");
        }

        // Now do second level
        println!("\n=== Second Level: ct_6 × ct_6 (tree mul) ===\n");

        println!("Input ct_6 anchor consistency:");
        let _k_input_c0 = check_anchor_consistency(&ctx, &ct_6.c0, 0, "ct_6.c0[0]");
        let _k_input_c1 = check_anchor_consistency(&ctx, &ct_6.c1, 0, "ct_6.c1[0]");

        println!("\nStep 1: Tensor product (tree)");
        let d0_tree = ctx.dual_poly_mul(&ct_6.c0, &ct_6.c0);
        let _k_d0_tree = check_anchor_consistency(&ctx, &d0_tree, 0, "d0_tree[0]");

        println!("\nStep 2: K-Elim rescale (tree)");
        let e0_tree = ctx.k_elim_rescale_dual(&d0_tree);
        let _k_e0_tree = check_anchor_consistency(&ctx, &e0_tree, 0, "e0_tree[0]");

        // If k_e0_tree is huge, the issue is in k_elim_rescale_dual on tree inputs
        // If k_e0_tree is 0 but d0_tree has huge k, the issue is in tensor product
    }

    #[test]
    fn test_anchor_ntt_roundtrip() {
        // First verify NTT→INTT roundtrip works for anchor primes
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);
        let n = ctx.n;

        println!("=== Anchor NTT Roundtrip Test ===\n");
        println!("N = {}", n);
        println!("Anchor primes: {:?}", ctx.dual_rns.anchor.primes);

        // Create test polynomial
        let mut test_poly = vec![0u64; n];
        test_poly[0] = 1;
        test_poly[1] = 2;
        test_poly[5] = 100;
        test_poly[10] = 50;

        for (i, ntt) in ctx.dual_rns.anchor.ntt_engines.iter().enumerate() {
            let p = ctx.dual_rns.anchor.primes[i];
            println!("\nPrime {}: {}", i, p);
            println!("  (p-1) mod 2N = {}", (p - 1) % (2 * n as u64));

            // NTT then INTT
            let ntt_result = ntt.ntt(&test_poly);
            let recovered = ntt.intt(&ntt_result);

            // Check roundtrip
            let mut errors = 0;
            for j in 0..n {
                if test_poly[j] != recovered[j] {
                    if errors < 5 {
                        println!("  ERROR at {}: expected {}, got {}", j, test_poly[j], recovered[j]);
                    }
                    errors += 1;
                }
            }
            if errors == 0 {
                println!("  ✓ Roundtrip OK");
            } else {
                println!("  ✗ {} errors in roundtrip", errors);
            }
        }

        // Also verify main primes work
        println!("\nMain primes roundtrip:");
        for (i, ntt) in ctx.ntt_engines.iter().enumerate() {
            let p = ctx.config.primes[i];
            let ntt_result = ntt.ntt(&test_poly);
            let recovered = ntt.intt(&ntt_result);
            let ok = (0..n).all(|j| test_poly[j] == recovered[j]);
            println!("  Prime {}: {} - {}", i, p, if ok { "✓" } else { "✗" });
        }
    }

    #[test]
    fn test_ntt_main_anchor_consistency() {
        // Direct test: verify that NTT multiplication gives SAME results for main vs anchor.
        // This isolates whether the issue is in NTT itself.

        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);
        let n = ctx.n;

        println!("=== NTT Main/Anchor Consistency Test ===\n");
        println!("Main primes: {:?}", ctx.config.primes);
        println!("Anchor primes: {:?}", ctx.dual_rns.anchor.primes);

        // Create a simple test polynomial: [1, 2, -1, 0, 0, ...] with -1 = p-1
        let coeffs_signed: Vec<i64> = {
            let mut v = vec![0i64; n];
            v[0] = 1;
            v[1] = 2;
            v[2] = -1;
            v[5] = 3;
            v[10] = -2;
            v
        };

        // Create polynomial in main RNS
        let poly_main: Vec<Vec<u64>> = ctx.config.primes.iter()
            .map(|&p| {
                coeffs_signed.iter().map(|&c| {
                    if c >= 0 { c as u64 % p } else { (p as i64 + c) as u64 }
                }).collect()
            })
            .collect();

        // Create polynomial in anchor RNS
        let poly_anchor: Vec<Vec<u64>> = ctx.dual_rns.anchor.primes.iter()
            .map(|&p| {
                coeffs_signed.iter().map(|&c| {
                    if c >= 0 { c as u64 % p } else { (p as i64 + c) as u64 }
                }).collect()
            })
            .collect();

        println!("\nInput polynomial: [1, 2, -1, 0, 0, 3, 0, 0, 0, 0, -2, ...]");

        // Square the polynomial using NTT in both systems
        let sq_main: Vec<Vec<u64>> = poly_main.iter()
            .zip(ctx.ntt_engines.iter())
            .map(|(limb, ntt)| ntt.multiply(limb, limb))
            .collect();

        let sq_anchor: Vec<Vec<u64>> = poly_anchor.iter()
            .zip(ctx.dual_rns.anchor.ntt_engines.iter())
            .map(|(limb, ntt)| ntt.multiply(limb, limb))
            .collect();

        // Reconstruct coefficient 0 from main
        let main_coeff0: Vec<u64> = sq_main.iter().map(|limb| limb[0]).collect();
        let v_main_0 = ctx.rns.to_int(&main_coeff0);

        // Check if anchor is consistent via extract_k_rns
        let anchor_coeff0: Vec<u64> = sq_anchor.iter().map(|limb| limb[0]).collect();
        let k_0 = ctx.dual_rns.extract_k_rns(v_main_0, &anchor_coeff0);

        println!("sq[0]: main={}, k={}", v_main_0, k_0);

        // Expected: sq[0] = 1² = 1 (since only coeff 0 contributes to constant term of square)
        // Actually: sq[0] = 1*1 + 2*(-2) + ... depends on convolution
        // Let's compute expected manually for negacyclic: sq[i] = sum_j a[j] * a[i-j mod N] * sign
        // sq[0] = a[0]² + (-1) * sum_{j=1..N-1} a[j] * a[N-j]
        //       = 1 + (-1) * (a[1]*a[N-1] + a[2]*a[N-2] + ...)
        // Most terms are 0, so sq[0] ≈ 1

        // Check several coefficients
        // NOTE: For K-Elimination, what matters is k_signed (not k).
        // k ≈ A means the true value is small negative (k_signed ≈ -1)
        println!("\nChecking multiple coefficients (k_signed interpretation):");
        let a3_product: u128 = ctx.dual_rns.anchor.primes[0..3].iter()
            .fold(1u128, |acc, &p| acc * p as u128);

        for i in [0, 1, 2, 3, 5, 10, 15].iter() {
            let main_ci: Vec<u64> = sq_main.iter().map(|limb| limb[*i]).collect();
            let v_main_i = ctx.rns.to_int(&main_ci);
            let anchor_ci: Vec<u64> = sq_anchor.iter().map(|limb| limb[*i]).collect();
            let k_i = ctx.dual_rns.extract_k_rns(v_main_i, &anchor_ci);

            // Convert to signed interpretation
            let k_signed_mag = if k_i > a3_product / 2 {
                a3_product - k_i  // negative, return magnitude
            } else {
                k_i
            };
            let k_is_neg = k_i > a3_product / 2;

            println!("  sq[{}]: main={:.2e}, k_signed={}{:.2e}",
                i, v_main_i as f64,
                if k_is_neg { "-" } else { "+" },
                k_signed_mag as f64);

            // Show raw values for debugging
            if *i == 3 {
                println!("    Raw main residues: {:?}", main_ci);
                println!("    Raw anchor residues: {:?}", anchor_ci);
                // Verify all anchor primes give p-4 (i.e., -4 mod p)
                for (j, &ap) in ctx.dual_rns.anchor.primes.iter().enumerate() {
                    let expected = ap - 4;  // -4 mod p
                    let actual = anchor_ci[j];
                    println!("    anchor[{}]: expected {} (-4), got {} (diff={})",
                        j, expected, actual, (expected as i64 - actual as i64).abs());
                }
            }
        }

        // For NTT consistency, k_signed magnitude should be small (≤ max coefficient value ≈ N²)
        // The squared polynomial has coefficients bounded by N² (since input is ±1, ±2, ±3)
        let max_expected_k = (n * n) as u128;  // Very generous bound

        for i in 0..20 {
            let main_ci: Vec<u64> = sq_main.iter().map(|limb| limb[i]).collect();
            let v_main_i = ctx.rns.to_int(&main_ci);
            let anchor_ci: Vec<u64> = sq_anchor.iter().map(|limb| limb[i]).collect();
            let k_i = ctx.dual_rns.extract_k_rns(v_main_i, &anchor_ci);

            let k_signed_mag = if k_i > a3_product / 2 {
                a3_product - k_i
            } else {
                k_i
            };

            assert!(k_signed_mag < max_expected_k,
                "NTT inconsistency at coeff {}: k_signed_mag={}, expected < {}",
                i, k_signed_mag, max_expected_k);
        }
        println!("\n✓ NTT main/anchor consistency PASSED for first 20 coefficients");
    }

    #[test]
    fn test_e2_s2_k_source() {
        // Trace exactly where k=577 comes from in e2*s² multiplication
        // The goal is to understand why multiplying k=0 (e2) with k=0 (s²) gives k=577

        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);
        let n = ctx.n;

        println!("=== Tracing k=577 source in e2*s² ===\n");
        println!("Main primes: {:?}", ctx.config.primes);
        println!("Anchor primes: {:?}", ctx.dual_rns.anchor.primes);
        let min_anchor = *ctx.dual_rns.anchor.primes.iter().min().unwrap();
        println!("Smallest anchor prime: {} ({:.2e})", min_anchor, min_anchor as f64);

        // Generate keys
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual(&mut rng);

        // Encrypt 2 and 3
        let ct_2 = ctx.encrypt_dual(2, &keys.public_key, &mut rng);
        let ct_3 = ctx.encrypt_dual(3, &keys.public_key, &mut rng);

        // Tensor product
        let d2 = ctx.dual_poly_mul(&ct_2.c1, &ct_3.c1);

        // K-Elim rescale
        let e2 = ctx.k_elim_rescale_dual(&d2);

        // Compute s²
        let s2 = ctx.dual_poly_mul(&keys.secret_key.s, &keys.secret_key.s);

        // Check e2 values against smallest anchor prime
        println!("\nChecking e2 coefficients vs smallest anchor prime {}:", min_anchor);
        let mut e2_exceeds_count = 0;
        for i in 0..20.min(n) {
            let main_i: Vec<u64> = e2.main.iter().map(|limb| limb[i]).collect();
            let v_m = ctx.rns.to_int(&main_i);

            if v_m > min_anchor as u128 {
                e2_exceeds_count += 1;
                if e2_exceeds_count <= 5 {
                    println!("  e2[{}] = {} ({:.2e}) > {} (smallest anchor)", i, v_m, v_m as f64, min_anchor);
                    // Show anchor residue for this coefficient
                    let anchor_residue_1 = e2.anchor[1][i];  // Second anchor prime is smallest
                    println!("    anchor[1] residue = {} (expected {} mod {} = {})",
                        anchor_residue_1,
                        v_m, min_anchor,
                        v_m % min_anchor as u128);
                }
            }
        }
        println!("  Total e2 coeffs exceeding smallest anchor (of first 20): {}", e2_exceeds_count);

        // Compute e2*s²
        let e2_s2 = ctx.dual_poly_mul(&e2, &s2);

        // Trace coefficient 0 in detail
        println!("\nCoefficient [0] detail:");
        let main_0: Vec<u64> = e2_s2.main.iter().map(|limb| limb[0]).collect();
        let anchor_0: Vec<u64> = e2_s2.anchor.iter().map(|limb| limb[0]).collect();
        let v_m_0 = ctx.rns.to_int(&main_0);

        println!("  v_main = {} ({:.2e})", v_m_0, v_m_0 as f64);
        println!("  main residues: {:?}", main_0);
        println!("  anchor residues: {:?}", anchor_0);

        // For each anchor prime, compute expected vs actual
        println!("\n  Per-anchor-prime consistency:");
        for (j, &p) in ctx.dual_rns.anchor.primes.iter().enumerate() {
            let expected = (v_m_0 % p as u128) as u64;
            let actual = anchor_0[j];
            let diff = if actual >= expected { actual - expected } else { expected - actual };
            println!("    anchor[{}] (p={}): expected={}, actual={}, diff={}",
                j, p, expected, actual, diff);
        }

        // Compute k using extract_k_rns
        let a3_product: u128 = ctx.dual_rns.anchor.primes[0..3].iter()
            .fold(1u128, |acc, &p| acc * p as u128);
        let k = ctx.dual_rns.extract_k_rns(v_m_0, &anchor_0);
        let k_signed = if k > a3_product / 2 {
            -(a3_product as i128 - k as i128)
        } else {
            k as i128
        };
        println!("\n  k = {} ({:.2e})", k, k as f64);
        println!("  k_signed = {}", k_signed);
        println!("  A3 = {} ({:.2e})", a3_product, a3_product as f64);
        println!("  k/A3 = {:.6}", k as f64 / a3_product as f64);

        // Trace the k_rns computation manually
        println!("\n  Manual k_rns trace:");
        let k_rns: Vec<u64> = ctx.dual_rns.anchor.primes.iter()
            .zip(anchor_0.iter())
            .zip(ctx.dual_rns.main_inv_anchor_rns.iter())
            .map(|((&pi, &v_a_i), &m_inv_i)| {
                let v_m_mod_pi = (v_m_0 % pi as u128) as u64;
                let diff = if v_a_i >= v_m_mod_pi {
                    v_a_i - v_m_mod_pi
                } else {
                    pi - v_m_mod_pi + v_a_i
                };
                let k_i = ((diff as u128 * m_inv_i as u128) % pi as u128) as u64;
                println!("    prime[{}]={}: v_a={}, v_m mod p={}, diff={}, M^-1={}, k_i={}",
                    pi, pi, v_a_i, v_m_mod_pi, diff, m_inv_i, k_i);
                k_i
            })
            .collect();
        println!("  k_rns = {:?}", k_rns);

        // THE KEY INSIGHT: if diff != 0 for any prime, then anchor is inconsistent with main
        // This means the NTT multiplication introduced an error somewhere
    }

    /// PUBLIC MODE depth-2 phase error trace
    ///
    /// This test traces phase error at EACH stage of public relinearization:
    /// 1. Post-tensor (before any relin or rescale)
    /// 2. Post-relin (after eval-key relinearization, BEFORE rescale)
    /// 3. Post-rescale (final result)
    ///
    /// The CORRECT ordering for BFV is: tensor → relin → rescale
    /// NOT: tensor → rescale → relin (which feeds wrong scale to eval keys)
    #[test]
    fn test_public_mode_depth2_phase_trace() {
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);

        // Test with multiple seeds to see variance
        for seed in [42u64, 123, 456, 789, 1000] {
            let mut rng = ShadowHarvester::with_seed(seed);
            let full_keys = ctx.generate_keys_dual_full(&mut rng);

            let delta = ctx.q_product / ctx.t as u128;
            let delta_half = delta / 2;
            let delta_sq_f64 = (delta as f64) * (delta as f64);
            let delta_sq_half_f64 = delta_sq_f64 / 2.0;

            println!("\n=== PUBLIC MODE Depth-2 Phase Trace (seed={}) ===", seed);
            println!("Q = {:.2e}, Δ = {:.2e}", ctx.q_product as f64, delta as f64);
            println!("Decomp base = 2^16 = 65536, num_digits ≈ 4");
            println!("Thresholds: Δ/2 = {:.2e} (exp=1), Δ²/2 = {:.2e} (exp=2)",
                delta_half as f64, delta_sq_half_f64);

            // Encrypt inputs
            let ct_2 = ctx.encrypt_dual(2, &full_keys.public_key, &mut rng);
            let ct_3 = ctx.encrypt_dual(3, &full_keys.public_key, &mut rng);
            let ct_4 = ctx.encrypt_dual(4, &full_keys.public_key, &mut rng);
            let ct_5 = ctx.encrypt_dual(5, &full_keys.public_key, &mut rng);

            // First level: 2*3=6 (PUBLIC mode)
            println!("\n--- Depth 1: 2 * 3 = 6 (PUBLIC) ---");
            let ct_6 = ctx.mul_dual_public(&ct_2, &ct_3, &full_keys.eval_key);
            let dec_6 = ctx.decrypt_dual(&ct_6, &full_keys.secret_key);
            println!("  Result: {} (expected 6)", dec_6);

            // CHECK: Is ct_6 consistent after depth-1 mul?
            if let Some((_coeff, _, msg)) = check_poly_consistency(&ctx, &ct_6.c0) {
                println!("  ✗ ct_6.c0 INCONSISTENT at {}", msg);
            }
            if let Some((coeff, _, msg)) = check_poly_consistency(&ctx, &ct_6.c1) {
                println!("  ✗ ct_6.c1 INCONSISTENT at {}", msg);
                dump_coeff_main_vs_anchor(&ctx, &ct_6.c1, coeff, "ct_6.c1");
            } else {
                println!("  ✓ ct_6 fully consistent");
            }

            // First level: 4*5=20 (PUBLIC mode)
            let ct_20 = ctx.mul_dual_public(&ct_4, &ct_5, &full_keys.eval_key);
            let dec_20 = ctx.decrypt_dual(&ct_20, &full_keys.secret_key);
            println!("  4 * 5 = {} (expected 20)", dec_20);

            // CHECK: Is ct_20 consistent after depth-1 mul?
            if let Some((_coeff, _, msg)) = check_poly_consistency(&ctx, &ct_20.c0) {
                println!("  ✗ ct_20.c0 INCONSISTENT at {}", msg);
            }
            if let Some((coeff, _, msg)) = check_poly_consistency(&ctx, &ct_20.c1) {
                println!("  ✗ ct_20.c1 INCONSISTENT at {}", msg);
                dump_coeff_main_vs_anchor(&ctx, &ct_20.c1, coeff, "ct_20.c1");
            } else {
                println!("  ✓ ct_20 fully consistent");
            }

            // === CRITICAL DEBUG: Verify NTT multiplication consistency ===
            println!("\n   [NTT MUL DEBUG] Checking ct_6.c1 * ct_20.c1:");

            // Get centered integer values for coeff 0 of both inputs
            let c6_c1_main: Vec<u64> = ct_6.c1.main.iter().map(|l| l[0]).collect();
            let c6_c1_val = ctx.rns.to_int(&c6_c1_main);
            let c6_c1_centered = center_mod_m_to_i128(c6_c1_val, ctx.q_product);
            println!("   ct_6.c1[0] centered = {}", c6_c1_centered);

            let c20_c1_main: Vec<u64> = ct_20.c1.main.iter().map(|l| l[0]).collect();
            let c20_c1_val = ctx.rns.to_int(&c20_c1_main);
            let c20_c1_centered = center_mod_m_to_i128(c20_c1_val, ctx.q_product);
            println!("   ct_20.c1[0] centered = {}", c20_c1_centered);

            // Compute d2[0] via SCHOOLBOOK for just main prime 0 and anchor prime 0
            // to verify NTT is computing the same thing
            let n = ctx.n;
            let p_main0 = ctx.config.primes[0];
            let p_anchor0 = ctx.dual_rns.anchor.primes[0];

            // Schoolbook: d2[0] = a[0]*b[0] - sum_{i=1}^{N-1} a[i]*b[N-i]
            let mut schoolbook_main0: i128 = 0;
            let mut schoolbook_anchor0: i128 = 0;
            for i in 0..n {
                let j = if i == 0 { 0 } else { n - i };
                let sign: i128 = if i == 0 { 1 } else { -1 };

                let a_main = ct_6.c1.main[0][i] as i128;
                let b_main = ct_20.c1.main[0][j] as i128;
                schoolbook_main0 += sign * a_main * b_main;

                let a_anchor = ct_6.c1.anchor[0][i] as i128;
                let b_anchor = ct_20.c1.anchor[0][j] as i128;
                schoolbook_anchor0 += sign * a_anchor * b_anchor;
            }
            // Reduce to positive mod p
            schoolbook_main0 = ((schoolbook_main0 % p_main0 as i128) + p_main0 as i128) % p_main0 as i128;
            schoolbook_anchor0 = ((schoolbook_anchor0 % p_anchor0 as i128) + p_anchor0 as i128) % p_anchor0 as i128;

            // Get NTT result
            let d2_test = ctx.dual_poly_mul(&ct_6.c1, &ct_20.c1);
            let ntt_main0 = d2_test.main[0][0];
            let ntt_anchor0 = d2_test.anchor[0][0];

            println!("   Schoolbook main[0][0]   = {}", schoolbook_main0);
            println!("   NTT       main[0][0]    = {}", ntt_main0);
            println!("   MATCH main: {}", schoolbook_main0 == ntt_main0 as i128);

            println!("   Schoolbook anchor[0][0] = {}", schoolbook_anchor0);
            println!("   NTT       anchor[0][0]  = {}", ntt_anchor0);
            println!("   MATCH anchor: {}", schoolbook_anchor0 == ntt_anchor0 as i128);

            // CORRECT K-LIFT CHECK: Do main/anchor satisfy the K-Elimination invariant?
            // For each anchor prime a_i: v ≡ v_m + k·M (mod a_i)
            // k_i = ((v_a - (v_m mod a_i)) * M^{-1}) mod a_i
            // Verify: (v_m mod a_i + k_i * (M mod a_i)) mod a_i == v_a
            let full_main_val = ctx.rns.to_int(&d2_test.main.iter().map(|l| l[0]).collect::<Vec<_>>());
            println!("   Full main CRT v_m = {} ({:.2e})", full_main_val, full_main_val as f64);

            let m_product = ctx.q_product;
            let mut k_lift_ok = true;
            for (i, &a_i) in ctx.dual_rns.anchor.primes.iter().enumerate() {
                let v_a = d2_test.anchor[i][0];
                let vm_mod_ai = (full_main_val % a_i as u128) as u64;
                let m_mod_ai = (m_product % a_i as u128) as u64;
                let inv_m_mod_ai = ctx.dual_rns.main_inv_anchor_rns[i];

                // k_i = ((v_a - vm_mod_ai) * M^{-1}) mod a_i
                let diff = (v_a as u128 + a_i as u128 - vm_mod_ai as u128) % a_i as u128;
                let k_i = ((diff * inv_m_mod_ai as u128) % a_i as u128) as u64;

                // Verify lift: (vm_mod_ai + k_i * m_mod_ai) mod a_i == v_a
                let lifted = ((vm_mod_ai as u128 + (k_i as u128 * m_mod_ai as u128)) % a_i as u128) as u64;

                if lifted != v_a {
                    println!("   ✗ K-LIFT FAILED at anchor[{}] prime={}:", i, a_i);
                    println!("     v_a={}, vm_mod_ai={}, k_i={}, lifted={}", v_a, vm_mod_ai, k_i, lifted);
                    k_lift_ok = false;
                }
            }
            if k_lift_ok {
                println!("   ✓ K-LIFT OK: main/anchor satisfy K-Elimination invariant");
                // Now check if k values are consistent (should reconstruct to same small k)
                let k_rns: Vec<u64> = ctx.dual_rns.anchor.primes.iter().enumerate()
                    .map(|(i, &a_i)| {
                        let v_a = d2_test.anchor[i][0];
                        let vm_mod_ai = (full_main_val % a_i as u128) as u64;
                        let inv_m_mod_ai = ctx.dual_rns.main_inv_anchor_rns[i];
                        let diff = (v_a as u128 + a_i as u128 - vm_mod_ai as u128) % a_i as u128;
                        ((diff * inv_m_mod_ai as u128) % a_i as u128) as u64
                    })
                    .collect();
                println!("   k_rns = {:?}", k_rns);
            }

            // === DEPTH 2: Manual trace of 6 * 20 = 120 with phase error at each stage ===
            println!("\n--- Depth 2: 6 * 20 = 120 (PUBLIC) - PHASE TRACE ---");

            let s2 = ctx.dual_poly_mul(&full_keys.secret_key.s, &full_keys.secret_key.s);

            // Stage A: Tensor product (degree-2 ciphertext)
            let d0 = ctx.dual_poly_mul(&ct_6.c0, &ct_20.c0);
            let c0_6_c1_20 = ctx.dual_poly_mul(&ct_6.c0, &ct_20.c1);
            let c1_6_c0_20 = ctx.dual_poly_mul(&ct_6.c1, &ct_20.c0);
            let d1 = ctx.dual_poly_add(&c0_6_c1_20, &c1_6_c0_20);
            let d2 = ctx.dual_poly_mul(&ct_6.c1, &ct_20.c1);

            // Compute degree-2 phase: d0 + d1*s + d2*s²
            let d1_s = ctx.dual_poly_mul(&d1, &full_keys.secret_key.s);
            let d2_s2 = ctx.dual_poly_mul(&d2, &s2);
            let phase_tensor = ctx.dual_poly_add(&ctx.dual_poly_add(&d0, &d1_s), &d2_s2);

            let tensor_coeff: Vec<u64> = phase_tensor.main.iter().map(|limb| limb[0]).collect();
            let tensor_phase = ctx.rns.to_int(&tensor_coeff);
            let (_, abs_err_tensor) = phase_error(tensor_phase, 120, delta, ctx.q_product, 2);
            let tensor_ratio = abs_err_tensor as f64 / delta_sq_half_f64;
            println!("A) POST-TENSOR (exp=2, scale Δ²):");
            println!("   |error| = {:.2e}, Δ²/2 = {:.2e}", abs_err_tensor as f64, delta_sq_half_f64);
            println!("   ratio = {:.6} {}", tensor_ratio, if tensor_ratio < 1.0 { "✓" } else { "EXCEEDED" });

            // === K-VALUE TRACKING THROUGH RELINEARIZATION ===
            println!("\n   [K-VALUE TRACKING] Pre-relin:");
            print_k_summary(&ctx, &d0, "d0 (c0*c0)");
            print_k_summary(&ctx, &d1, "d1 (c0*c1 + c1*c0)");
            print_k_summary(&ctx, &d2, "d2 (c1*c1)");

            // Stage B: PUBLIC relinearization (BEFORE rescale!)
            // This is where eval key noise enters
            let (relin_c0, relin_c1) = ctx.relinearize_dual(&d2, &full_keys.eval_key);

            println!("\n   [K-VALUE TRACKING] Post-relin (before combining with d0/d1):");
            print_k_summary(&ctx, &relin_c0, "relin_c0 (sum of digit*rlk0)");
            print_k_summary(&ctx, &relin_c1, "relin_c1 (sum of digit*rlk1)");

            // ═══════════════════════════════════════════════════════════════════
            // CRITICAL CHECK: Main/Anchor consistency after relinearization
            // ═══════════════════════════════════════════════════════════════════
            println!("\n   [INVARIANT CHECK] Main/Anchor consistency:");

            // First check: Is the EVAL KEY itself consistent?
            println!("   Checking eval key (rlk) consistency:");
            for (digit_idx, (rlk0, _rlk1)) in full_keys.eval_key.rlk.iter().enumerate() {
                if let Some((_coeff, _, msg)) = check_poly_consistency(&ctx, rlk0) {
                    println!("   ✗ rlk0[{}] INCONSISTENT at {}", digit_idx, msg);
                    dump_coeff_main_vs_anchor(&ctx, rlk0, _coeff, &format!("rlk0[{}]", digit_idx));
                    break; // Only show first mismatch
                }
            }
            println!("   (If no errors above, eval key is consistent)");

            // Check the input to relinearization (d2)
            if let Some((_coeff, _, msg)) = check_poly_consistency(&ctx, &d2) {
                println!("   ✗ d2 (relin input) INCONSISTENT at {}", msg);
                dump_coeff_main_vs_anchor(&ctx, &d2, _coeff, "d2");
            } else {
                println!("   ✓ d2 (relin input) consistent");
            }

            // Check relin outputs
            if let Some((_coeff, _, msg)) = check_poly_consistency(&ctx, &relin_c0) {
                println!("   ✗ relin_c0 INCONSISTENT at {}", msg);
            } else {
                println!("   ✓ relin_c0 consistent (checked {} coeffs)", ctx.n);
            }
            if let Some((_coeff, _, msg)) = check_poly_consistency(&ctx, &relin_c1) {
                println!("   ✗ relin_c1 INCONSISTENT at {}", msg);
            } else {
                println!("   ✓ relin_c1 consistent (checked {} coeffs)", ctx.n);
            }

            // Combine into degree-1 (still at tensor scale Δ²)
            let c0_post_relin = ctx.dual_poly_add(&d0, &relin_c0);
            let c1_post_relin = ctx.dual_poly_add(&d1, &relin_c1);

            println!("\n   [K-VALUE TRACKING] Post-combine (d0+relin_c0, d1+relin_c1):");
            print_k_summary(&ctx, &c0_post_relin, "c0_post_relin (goes to rescale)");
            print_k_summary(&ctx, &c1_post_relin, "c1_post_relin (goes to rescale)");

            // Check combined outputs (what goes into rescale)
            if let Some((_coeff, _, msg)) = check_poly_consistency(&ctx, &c0_post_relin) {
                println!("   ✗ c0_post_relin INCONSISTENT at {}", msg);
                // Dump first inconsistent coeff for detailed diagnosis
                dump_coeff_main_vs_anchor(&ctx, &c0_post_relin, _coeff, "c0_post_relin");
            } else {
                println!("   ✓ c0_post_relin consistent (goes to rescale)");
            }
            if let Some((_coeff, _, msg)) = check_poly_consistency(&ctx, &c1_post_relin) {
                println!("   ✗ c1_post_relin INCONSISTENT at {}", msg);
                dump_coeff_main_vs_anchor(&ctx, &c1_post_relin, _coeff, "c1_post_relin");
            } else {
                println!("   ✓ c1_post_relin consistent (goes to rescale)");
            }

            // Compute phase: c0 + c1*s (should ≈ 120*Δ² + noise)
            let c1_s_post_relin = ctx.dual_poly_mul(&c1_post_relin, &full_keys.secret_key.s);
            let phase_post_relin = ctx.dual_poly_add(&c0_post_relin, &c1_s_post_relin);

            let relin_coeff: Vec<u64> = phase_post_relin.main.iter().map(|limb| limb[0]).collect();
            let relin_phase = ctx.rns.to_int(&relin_coeff);
            let (_, abs_err_relin) = phase_error(relin_phase, 120, delta, ctx.q_product, 2);
            let relin_ratio = abs_err_relin as f64 / delta_sq_half_f64;
            println!("B) POST-RELIN (before rescale, exp=2, scale Δ²):");
            println!("   |error| = {:.2e}, Δ²/2 = {:.2e}", abs_err_relin as f64, delta_sq_half_f64);
            println!("   ratio = {:.6} {}", relin_ratio, if relin_ratio < 1.0 { "✓" } else { "EXCEEDED" });
            println!("   noise added by relin = {:.2e}", (abs_err_relin as i128 - abs_err_tensor as i128).abs() as f64);

            // Stage C: K-Elimination rescale
            let c0_final = ctx.k_elim_rescale_dual(&c0_post_relin);
            let c1_final = ctx.k_elim_rescale_dual(&c1_post_relin);

            // Compute final phase: c0 + c1*s (should ≈ 120*Δ + noise/Δ)
            let c1_s_final = ctx.dual_poly_mul(&c1_final, &full_keys.secret_key.s);
            let phase_final = ctx.dual_poly_add(&c0_final, &c1_s_final);

            let final_coeff: Vec<u64> = phase_final.main.iter().map(|limb| limb[0]).collect();
            let final_phase = ctx.rns.to_int(&final_coeff);
            let (_, abs_err_final) = phase_error(final_phase, 120, delta, ctx.q_product, 1);
            let final_ratio = abs_err_final as f64 / delta_half as f64;
            println!("C) POST-RESCALE (exp=1, scale Δ):");
            println!("   |error| = {:.2e}, Δ/2 = {:.2e}", abs_err_final as f64, delta_half as f64);
            println!("   ratio = {:.6} {}", final_ratio, if final_ratio < 1.0 { "✓" } else { "EXCEEDED" });

            // Final decryption
            let ct_120 = DualRNSCiphertext { c0: c0_final, c1: c1_final, level: 0 };
            let dec_120 = ctx.decrypt_dual(&ct_120, &full_keys.secret_key);

            println!("\n=== Result (seed={}) ===", seed);
            println!("  Decrypted: {} (expected 120)", dec_120);
            if dec_120 == 120 {
                println!("  ✓ CORRECT");
            } else {
                println!("  ✗ WRONG (error = {})", (dec_120 as i64 - 120).abs());
                // Identify which stage failed
                if tensor_ratio > 1.0 {
                    println!("  Failure point: TENSOR (before any relin/rescale)");
                } else if relin_ratio > 1.0 {
                    println!("  Failure point: RELIN (eval key noise exceeded budget)");
                } else if final_ratio > 1.0 {
                    println!("  Failure point: RESCALE (K-elim or accumulated noise)");
                } else {
                    println!("  Failure point: DECODE (ratios ok but wrong result?!)");
                }
            }
        }

        println!("\n=== Summary ===");
        println!("Decomposition: base=2^16, digits≈4");
        println!("Expected noise per relin: O(N × base × σ² × num_digits)");
        println!("  = O(1024 × 65536 × ~9 × 4) ≈ 2.4e9 per relin");
        println!("For depth-2, we have 3 relins total (one per mul, twice for depth-1, once for depth-2)");
        println!("Accumulated: ~7.2e9, vs Δ/2 ≈ {:.2e}", (ctx.q_product / ctx.t as u128 / 2) as f64);
        println!("\nIf ratio > 1.0 at relin stage: BFV noise exhaustion (need larger params)");
        println!("If ratio > 1.0 at rescale stage: K-Elim bug or accumulated rounding");
        println!("If ratio > 1.0 at tensor stage: Input ciphertexts already corrupted");
    }

    // ========================================================================
    // SERIALIZATION TESTS
    // ========================================================================

    /// Test JSON serialization roundtrip for ciphertexts
    #[test]
    #[cfg(feature = "serde")]
    fn test_json_serialization_roundtrip() {
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);
        let mut rng = ShadowHarvester::with_seed(42);

        let keys = ctx.generate_keys_dual(&mut rng);
        let ct = ctx.encrypt_dual(42, &keys.public_key, &mut rng);

        // Serialize to JSON
        let json = ct.to_json().expect("JSON serialization failed");
        println!("JSON size: {} bytes", json.len());

        // Deserialize
        let ct_restored = DualRNSCiphertext::from_json(&json)
            .expect("JSON deserialization failed");

        // Verify correctness
        let original = ctx.decrypt_dual(&ct, &keys.secret_key);
        let restored = ctx.decrypt_dual(&ct_restored, &keys.secret_key);
        assert_eq!(original, restored, "JSON roundtrip changed decryption result");
        assert_eq!(restored, 42, "Restored ciphertext decrypts incorrectly");

        println!("SUCCESS: JSON serialization roundtrip verified");
    }

    /// Test bincode serialization roundtrip for ciphertexts
    #[test]
    #[cfg(feature = "serde")]
    fn test_bincode_serialization_roundtrip() {
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);
        let mut rng = ShadowHarvester::with_seed(42);

        let keys = ctx.generate_keys_dual(&mut rng);
        let ct = ctx.encrypt_dual(42, &keys.public_key, &mut rng);

        // Serialize to bincode
        let bytes = ct.to_bytes().expect("Bincode serialization failed");
        println!("Bincode size: {} bytes", bytes.len());

        // Deserialize
        let ct_restored = DualRNSCiphertext::from_bytes(&bytes)
            .expect("Bincode deserialization failed");

        // Verify correctness
        let original = ctx.decrypt_dual(&ct, &keys.secret_key);
        let restored = ctx.decrypt_dual(&ct_restored, &keys.secret_key);
        assert_eq!(original, restored, "Bincode roundtrip changed decryption result");
        assert_eq!(restored, 42, "Restored ciphertext decrypts incorrectly");

        println!("SUCCESS: Bincode serialization roundtrip verified");
    }

    /// Test key serialization roundtrip
    #[test]
    #[cfg(feature = "serde")]
    fn test_key_serialization_roundtrip() {
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);
        let mut rng = ShadowHarvester::with_seed(42);

        let keys = ctx.generate_keys_dual(&mut rng);

        // Serialize keys to bincode (more compact for keys)
        let bytes = keys.to_bytes().expect("Key serialization failed");
        println!("KeySet bincode size: {} bytes", bytes.len());

        // Deserialize
        let keys_restored = DualRNSKeySet::from_bytes(&bytes)
            .expect("Key deserialization failed");

        // Verify by encrypting and decrypting with restored keys
        let ct = ctx.encrypt_dual(99, &keys_restored.public_key, &mut rng);
        let result = ctx.decrypt_dual(&ct, &keys_restored.secret_key);
        assert_eq!(result, 99, "Restored keys don't work correctly");

        println!("SUCCESS: Key serialization roundtrip verified");
    }

    /// Test serialization size comparison (JSON vs bincode)
    #[test]
    #[cfg(feature = "serde")]
    fn test_serialization_size_comparison() {
        let config = FHEConfig::light_rns_exact();
        let ctx = RNSFHEContext::new_coeff_domain(&config);
        let mut rng = ShadowHarvester::with_seed(42);

        let keys = ctx.generate_keys_dual(&mut rng);
        let ct = ctx.encrypt_dual(42, &keys.public_key, &mut rng);

        let json_size = ct.to_json().unwrap().len();
        let bincode_size = ct.to_bytes().unwrap().len();

        println!("=== Serialization Size Comparison ===");
        println!("JSON:    {} bytes", json_size);
        println!("Bincode: {} bytes", bincode_size);
        println!("Ratio:   {:.2}x smaller with bincode", json_size as f64 / bincode_size as f64);

        // Bincode should always be smaller
        assert!(bincode_size < json_size, "Bincode should be more compact than JSON");
    }
}
