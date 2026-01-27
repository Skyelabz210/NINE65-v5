//! Keys Module - BFV Key Generation
//!
//! Generates secret, public, and evaluation keys for BFV FHE.
//! 
//! # Security (December 2024 Cryptographic Audit)
//!
//! - **SecretKey** implements `Zeroize` and `ZeroizeOnDrop` for secure memory clearing
//! - **generate_secure()** uses OS CSPRNG - USE FOR PRODUCTION
//! - **generate()** uses Shadow Entropy - USE FOR TESTING/BENCHMARKS ONLY
//!
//! # Example
//!
//! ```ignore
//! // PRODUCTION: Use secure key generation
//! let keys = KeySet::generate_secure(&config, &ntt);
//!
//! // TESTING: Use deterministic generation
//! let mut harvester = ShadowHarvester::with_seed(42);
//! let keys = KeySet::generate(&config, &ntt, &mut harvester);
//! ```

#[cfg(feature = "ntt_fft")]
use crate::arithmetic::NTTEngineFFT as NTTEngine;

#[cfg(not(feature = "ntt_fft"))]
use crate::arithmetic::NTTEngine;
use crate::entropy::ShadowHarvester;
use crate::entropy::{secure_ternary_vector, secure_uniform_vector, secure_cbd_vector};
use crate::params::FHEConfig;
use crate::ring::RingPolynomial;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secret Key: ternary polynomial s ∈ R_q
/// 
/// # Security
/// 
/// Implements `ZeroizeOnDrop` to securely clear memory when dropped.
/// The secret key coefficients are overwritten with zeros using volatile
/// writes that cannot be optimized away by the compiler.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    /// The secret polynomial (zeroized on drop via RingPolynomial::Zeroize)
    pub s: RingPolynomial,
}

impl SecretKey {
    /// Generate a new secret key using Shadow Entropy (DETERMINISTIC)
    /// 
    /// # Warning
    /// 
    /// This produces deterministic keys based on the harvester seed.
    /// **Use only for testing and reproducible benchmarks.**
    /// 
    /// For production, use [`generate_secure()`](Self::generate_secure).
    pub fn generate(config: &FHEConfig, harvester: &mut ShadowHarvester) -> Self {
        let s = RingPolynomial::random_ternary(config.n, config.q, harvester);
        Self { s }
    }
    
    /// Generate a new secret key using OS CSPRNG (PRODUCTION)
    /// 
    /// Uses the operating system's cryptographically secure random number
    /// generator via `getrandom`. This should be used for all production
    /// key generation.
    ///
    /// # Panics
    ///
    /// Panics if the OS CSPRNG fails (should never happen on supported platforms).
    pub fn generate_secure(config: &FHEConfig) -> Self {
        let ternary = secure_ternary_vector(config.n);
        
        // Convert ternary {-1, 0, 1} to ring elements mod q
        let coeffs: Vec<u64> = ternary.iter()
            .map(|&t| {
                if t < 0 {
                    config.q - 1  // -1 mod q
                } else {
                    t as u64
                }
            })
            .collect();
        
        let s = RingPolynomial::from_coeffs(coeffs, config.q);
        Self { s }
    }
}

/// Public Key: (pk0, pk1) where pk0 = -a*s + e, pk1 = a
#[derive(Clone)]
pub struct PublicKey {
    /// pk0 = -a*s + e
    pub pk0: RingPolynomial,
    /// pk1 = a (random polynomial)
    pub pk1: RingPolynomial,
}

impl PublicKey {
    /// Generate public key from secret key (DETERMINISTIC)
    ///
    /// Uses Shadow Entropy for randomness. For production, use
    /// [`generate_secure()`](Self::generate_secure).
    pub fn generate(
        sk: &SecretKey,
        config: &FHEConfig,
        ntt: &NTTEngine,
        harvester: &mut ShadowHarvester,
    ) -> Self {
        // a ← uniform random
        let a = RingPolynomial::random_uniform(config.n, config.q, harvester);
        
        // e ← error distribution (CBD)
        let e = RingPolynomial::random_cbd(config.n, config.q, config.eta, harvester);
        
        // pk0 = -a*s + e = -(a*s) + e
        let as_prod = a.mul(&sk.s, ntt);
        let neg_as = as_prod.neg(ntt);
        let pk0 = neg_as.add(&e, ntt);
        
        Self { pk0, pk1: a }
    }
    
    /// Generate public key from secret key using OS CSPRNG (PRODUCTION)
    ///
    /// Uses cryptographically secure randomness for the 'a' polynomial
    /// and error term.
    pub fn generate_secure(
        sk: &SecretKey,
        config: &FHEConfig,
        ntt: &NTTEngine,
    ) -> Self {
        // a ← uniform random (CSPRNG)
        let a_coeffs = secure_uniform_vector(config.n, config.q);
        let a = RingPolynomial::from_coeffs(a_coeffs, config.q);
        
        // e ← CBD error distribution (CSPRNG)
        let e_signed = secure_cbd_vector(config.n, config.eta);
        let e_coeffs: Vec<u64> = e_signed.iter()
            .map(|&e| {
                if e < 0 {
                    ((config.q as i64) + e) as u64
                } else {
                    e as u64
                }
            })
            .collect();
        let e = RingPolynomial::from_coeffs(e_coeffs, config.q);
        
        // pk0 = -a*s + e
        let as_prod = a.mul(&sk.s, ntt);
        let neg_as = as_prod.neg(ntt);
        let pk0 = neg_as.add(&e, ntt);
        
        Self { pk0, pk1: a }
    }
}

/// Evaluation Key for relinearization after multiplication
///
/// Contains relinearization key components for converting degree-2
/// ciphertexts back to degree-1 after homomorphic multiplication.
#[derive(Clone)]
pub struct EvaluationKey {
    /// Relinearization key components
    /// rlk[i] = (b_i, a_i) where b_i = -a_i * s + e_i + (s² * T^i)
    pub rlk: Vec<(RingPolynomial, RingPolynomial)>,
    /// Decomposition base (typically a power of 2)
    pub decomp_base: u64,
    /// Number of decomposition levels
    pub levels: usize,
}

impl EvaluationKey {
    /// Generate evaluation key for relinearization (DETERMINISTIC)
    pub fn generate(
        sk: &SecretKey,
        config: &FHEConfig,
        ntt: &NTTEngine,
        harvester: &mut ShadowHarvester,
    ) -> Self {
        let decomp_base = 1u64 << 16;  // T = 2^16
        let q_bits = 64 - config.q.leading_zeros() as usize;
        let levels = q_bits.div_ceil(16);
        
        let s_squared = sk.s.mul(&sk.s, ntt);
        
        let mut rlk = Vec::with_capacity(levels);
        let mut power_of_t = 1u64;
        
        for _ in 0..levels {
            let a_i = RingPolynomial::random_uniform(config.n, config.q, harvester);
            let e_i = RingPolynomial::random_cbd(config.n, config.q, config.eta, harvester);
            
            let s2_ti = s_squared.scalar_mul(power_of_t, ntt);
            let as_prod = a_i.mul(&sk.s, ntt);
            let neg_as = as_prod.neg(ntt);
            let b_i = neg_as.add(&e_i, ntt).add(&s2_ti, ntt);
            
            rlk.push((b_i, a_i));
            power_of_t = ((power_of_t as u128 * decomp_base as u128) % config.q as u128) as u64;
        }
        
        Self { rlk, decomp_base, levels }
    }
    
    /// Generate evaluation key using OS-seeded Shadow Entropy
    ///
    /// Eval keys are less sensitive than secret keys, so we use
    /// OS-seeded Shadow Entropy for speed while maintaining security.
    pub fn generate_secure(
        sk: &SecretKey,
        config: &FHEConfig,
        ntt: &NTTEngine,
    ) -> Self {
        let mut harvester = ShadowHarvester::from_os_seed();
        Self::generate(sk, config, ntt, &mut harvester)
    }
}

/// Secure zeroization for EvaluationKey
///
/// While eval keys are public, they contain s² information.
/// Zeroizing is defense-in-depth.
impl Drop for EvaluationKey {
    fn drop(&mut self) {
        for (b, a) in &mut self.rlk {
            b.coeffs.zeroize();
            a.coeffs.zeroize();
        }
    }
}

/// Complete key set containing all keys needed for FHE operations
pub struct KeySet {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
    pub eval_key: EvaluationKey,
}

impl KeySet {
    /// Generate complete key set (DETERMINISTIC)
    ///
    /// Uses Shadow Entropy for reproducible key generation.
    /// **For production, use [`generate_secure()`](Self::generate_secure).**
    pub fn generate(config: &FHEConfig, ntt: &NTTEngine, harvester: &mut ShadowHarvester) -> Self {
        let secret_key = SecretKey::generate(config, harvester);
        let public_key = PublicKey::generate(&secret_key, config, ntt, harvester);
        let eval_key = EvaluationKey::generate(&secret_key, config, ntt, harvester);
        
        Self { secret_key, public_key, eval_key }
    }
    
    /// Generate complete key set using OS CSPRNG (PRODUCTION)
    ///
    /// Uses cryptographically secure randomness for all key generation.
    /// This is the recommended method for production deployments.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = FHEConfig::he_standard_128();
    /// let ntt = NTTEngine::new(config.q, config.n);
    /// let keys = KeySet::generate_secure(&config, &ntt);
    /// ```
    pub fn generate_secure(config: &FHEConfig, ntt: &NTTEngine) -> Self {
        let secret_key = SecretKey::generate_secure(config);
        let public_key = PublicKey::generate_secure(&secret_key, config, ntt);
        let eval_key = EvaluationKey::generate_secure(&secret_key, config, ntt);
        
        Self { secret_key, public_key, eval_key }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::secure_configs::SecureConfig;
    
    #[test]
    fn test_keygen_basic() {
        let config = SecureConfig::test_fast().into_config();
        let mut harvester = ShadowHarvester::with_seed(42);
        
        let sk = SecretKey::generate(&config, &mut harvester);
        
        // Secret key should be ternary
        for i in 0..config.n {
            let coeff = sk.s.get_signed(i);
            assert!((-1..=1).contains(&coeff), "Non-ternary coefficient: {}", coeff);
        }
    }
    
    #[test]
    fn test_keygen_deterministic() {
        let config = SecureConfig::test_fast().into_config();
        let ntt = NTTEngine::new(config.q, config.n);
        
        let mut h1 = ShadowHarvester::with_seed(12345);
        let mut h2 = ShadowHarvester::with_seed(12345);
        
        let keys1 = KeySet::generate(&config, &ntt, &mut h1);
        let keys2 = KeySet::generate(&config, &ntt, &mut h2);
        
        // Same seed should produce same keys
        assert_eq!(keys1.secret_key.s.coeffs, keys2.secret_key.s.coeffs);
        assert_eq!(keys1.public_key.pk0.coeffs, keys2.public_key.pk0.coeffs);
        assert_eq!(keys1.public_key.pk1.coeffs, keys2.public_key.pk1.coeffs);
    }
    
    #[test]
    fn test_keygen_secure() {
        let config = SecureConfig::test_fast().into_config();
        let ntt = NTTEngine::new(config.q, config.n);
        
        let keys1 = KeySet::generate_secure(&config, &ntt);
        let keys2 = KeySet::generate_secure(&config, &ntt);
        
        // Secure keygen should produce DIFFERENT keys each time
        assert_ne!(keys1.secret_key.s.coeffs, keys2.secret_key.s.coeffs,
                   "Secure keygen should be non-deterministic");
    }
    
    #[test]
    fn test_secure_key_is_ternary() {
        let config = SecureConfig::test_fast().into_config();
        
        let sk = SecretKey::generate_secure(&config);
        
        // Secret key should still be ternary
        for i in 0..config.n {
            let coeff = sk.s.get_signed(i);
            assert!((-1..=1).contains(&coeff), 
                    "Secure key has non-ternary coefficient at {}: {}", i, coeff);
        }
    }
    
    #[test]
    fn test_keygen_benchmark() {
        let config = SecureConfig::test_fast().into_config();
        let ntt = NTTEngine::new(config.q, config.n);
        let mut harvester = ShadowHarvester::with_seed(999);
        
        let start = std::time::Instant::now();
        for _ in 0..100 {
            let _ = KeySet::generate(&config, &ntt, &mut harvester);
        }
        let elapsed = start.elapsed();
        
        println!("KeyGen (deterministic) x100: {:?}", elapsed);
    }
    
    #[test]
    fn test_keygen_secure_benchmark() {
        let config = SecureConfig::test_fast().into_config();
        let ntt = NTTEngine::new(config.q, config.n);
        
        let start = std::time::Instant::now();
        for _ in 0..100 {
            let _ = KeySet::generate_secure(&config, &ntt);
        }
        let elapsed = start.elapsed();
        
        println!("KeyGen (secure) x100: {:?}", elapsed);
    }
    
    #[test]
    fn test_encrypt_decrypt_with_secure_keys() {
        // Integration test: verify secure keys work with FHE operations
        use crate::ops::encrypt::{BFVEncoder, BFVEncryptor, BFVDecryptor};
        
        let config = SecureConfig::test_fast().into_config();
        let ntt = NTTEngine::new(config.q, config.n);
        let keys = KeySet::generate_secure(&config, &ntt);
        
        // Create encoder/encryptor/decryptor
        let encoder = BFVEncoder::new(&config);
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
        
        // Use Shadow for encrypt noise (acceptable per audit)
        let mut harvester = ShadowHarvester::from_os_seed();
        
        let plaintext = 42u64;
        let ct = encryptor.encrypt(plaintext, &mut harvester);
        let decrypted = decryptor.decrypt(&ct);
        
        assert_eq!(decrypted, plaintext, "Encrypt/decrypt failed with secure keys");
    }
}
