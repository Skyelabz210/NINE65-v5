//! Encryption Module - BFV Encrypt/Decrypt
//!
//! BFV encoding: m → Δ*m where Δ = floor(q/t)
//! Encryption: ct = (pk0*u + e1 + Δ*m, pk1*u + e2)
//! Decryption: m = round(t * (c0 + c1*s) / q) mod t

#[cfg(feature = "ntt_fft")]
use crate::arithmetic::NTTEngineFFT as NTTEngine;

#[cfg(not(feature = "ntt_fft"))]
use crate::arithmetic::NTTEngine;
use crate::entropy::ShadowHarvester;
use crate::keys::{PublicKey, SecretKey};
use crate::params::FHEConfig;
use crate::ring::RingPolynomial;

/// BFV Encoder: handles message ↔ polynomial conversion
pub struct BFVEncoder {
    /// Ciphertext modulus
    pub q: u64,
    /// Plaintext modulus
    pub t: u64,
    /// Scaling factor Δ = floor(q/t)
    pub delta: u64,
    /// Polynomial degree
    pub n: usize,
}

impl BFVEncoder {
    /// Create a new encoder
    pub fn new(config: &FHEConfig) -> Self {
        Self {
            q: config.q,
            t: config.t,
            delta: config.q / config.t,
            n: config.n,
        }
    }
    
    /// Encode a scalar message as polynomial
    pub fn encode(&self, m: u64) -> RingPolynomial {
        assert!(m < self.t, "Message must be less than plaintext modulus");
        
        let mut coeffs = vec![0u64; self.n];
        coeffs[0] = ((self.delta as u128 * m as u128) % self.q as u128) as u64;
        
        RingPolynomial::from_coeffs(coeffs, self.q)
    }
    
    /// Decode polynomial to scalar message
    pub fn decode(&self, poly: &RingPolynomial) -> u64 {
        // m = round(t * c / q) mod t
        // Using integer formula: floor((2*t*c + q) / (2*q)) mod t
        let c = poly.coeffs[0];
        
        // Careful computation to avoid overflow
        let numerator = 2u128 * (self.t as u128) * (c as u128) + (self.q as u128);
        let denominator = 2u128 * (self.q as u128);
        let result = (numerator / denominator) as u64;
        
        result % self.t
    }
    
    /// Decode a polynomial from a degree-2 ciphertext (at Δ² level)
    /// 
    /// After tensor product, values are at Δ² level instead of Δ level.
    /// Use t²/q² scaling to recover message.
    /// 
    /// Formula: m = round(t² × coeff / q²) = round(coeff × t² / q²)
    pub fn decode_degree2(&self, poly: &RingPolynomial) -> u64 {
        let c = poly.coeffs[0];
        
        // Compute round(c * t² / q²)
        // Using: round(x/y) = (2x + y) / (2y)
        // 
        // But t² and q² might overflow u128. Let's be careful.
        // 
        // Alternative: c * t² / q² = c * t / q * t / q = (c * t / q) * t / q
        // First scale: temp = round(c * t / q)  
        // Second scale: result = round(temp * t / q)
        
        let temp = ((2u128 * self.t as u128 * c as u128) + self.q as u128) 
                   / (2u128 * self.q as u128);
        
        let result = ((2u128 * self.t as u128 * temp) + self.q as u128) 
                     / (2u128 * self.q as u128);
        
        (result as u64) % self.t
    }
    
    /// Encode a vector of messages (for batching)
    pub fn encode_vector(&self, msgs: &[u64]) -> RingPolynomial {
        assert!(msgs.len() <= self.n);
        
        let mut coeffs = vec![0u64; self.n];
        for (i, &m) in msgs.iter().enumerate() {
            assert!(m < self.t);
            coeffs[i] = ((self.delta as u128 * m as u128) % self.q as u128) as u64;
        }
        
        RingPolynomial::from_coeffs(coeffs, self.q)
    }
    
    /// Decode polynomial to vector of messages
    pub fn decode_vector(&self, poly: &RingPolynomial, len: usize) -> Vec<u64> {
        (0..len).map(|i| {
            let c = poly.coeffs[i];
            let numerator = 2u128 * (self.t as u128) * (c as u128) + (self.q as u128);
            let denominator = 2u128 * (self.q as u128);
            ((numerator / denominator) as u64) % self.t
        }).collect()
    }
}

/// BFV Ciphertext: (c0, c1) ∈ R_q × R_q
#[derive(Clone)]
pub struct Ciphertext {
    /// First component
    pub c0: RingPolynomial,
    /// Second component
    pub c1: RingPolynomial,
}

/// BFV Encryptor
pub struct BFVEncryptor<'a> {
    pub pk: &'a PublicKey,
    pub encoder: &'a BFVEncoder,
    pub ntt: &'a NTTEngine,
    pub eta: usize,
}

impl<'a> BFVEncryptor<'a> {
    pub fn new(pk: &'a PublicKey, encoder: &'a BFVEncoder, ntt: &'a NTTEngine, eta: usize) -> Self {
        Self { pk, encoder, ntt, eta }
    }
    
    /// Encrypt a message
    pub fn encrypt(&self, m: u64, harvester: &mut ShadowHarvester) -> Ciphertext {
        let plaintext = self.encoder.encode(m);
        self.encrypt_poly(&plaintext, harvester)
    }
    
    /// Encrypt with specific seed (deterministic)
    pub fn encrypt_seeded(&self, m: u64, seed: u64) -> Ciphertext {
        let mut harvester = ShadowHarvester::with_seed(seed);
        self.encrypt(m, &mut harvester)
    }
    
    /// Encrypt a polynomial
    pub fn encrypt_poly(&self, plaintext: &RingPolynomial, harvester: &mut ShadowHarvester) -> Ciphertext {
        let n = self.encoder.n;
        let q = self.encoder.q;
        
        // u ← ternary (blinding factor)
        let u = RingPolynomial::random_ternary(n, q, harvester);
        
        // e1, e2 ← error distribution
        let e1 = RingPolynomial::random_cbd(n, q, self.eta, harvester);
        let e2 = RingPolynomial::random_cbd(n, q, self.eta, harvester);
        
        // c0 = pk0 * u + e1 + plaintext
        let pk0_u = self.pk.pk0.mul(&u, self.ntt);
        let c0 = pk0_u.add(&e1, self.ntt).add(plaintext, self.ntt);
        
        // c1 = pk1 * u + e2
        let pk1_u = self.pk.pk1.mul(&u, self.ntt);
        let c1 = pk1_u.add(&e2, self.ntt);
        
        Ciphertext { c0, c1 }
    }
}

/// BFV Decryptor
pub struct BFVDecryptor<'a> {
    pub sk: &'a SecretKey,
    pub encoder: &'a BFVEncoder,
    pub ntt: &'a NTTEngine,
}

impl<'a> BFVDecryptor<'a> {
    pub fn new(sk: &'a SecretKey, encoder: &'a BFVEncoder, ntt: &'a NTTEngine) -> Self {
        Self { sk, encoder, ntt }
    }
    
    /// Decrypt ciphertext to message
    pub fn decrypt(&self, ct: &Ciphertext) -> u64 {
        let decrypted = self.decrypt_raw(ct);
        self.encoder.decode(&decrypted)
    }
    
    /// Decrypt to raw polynomial (before decoding)
    pub fn decrypt_raw(&self, ct: &Ciphertext) -> RingPolynomial {
        // m_noisy = c0 + c1 * s
        let c1_s = ct.c1.mul(&self.sk.s, self.ntt);
        ct.c0.add(&c1_s, self.ntt)
    }
    
    /// Decrypt a degree-2 ciphertext (d0, d1, d2)
    /// These are at Δ² level from tensor product, requires t²/q² scaling
    pub fn decrypt_degree2(&self, d0: &RingPolynomial, d1: &RingPolynomial, d2: &RingPolynomial) -> u64 {
        let s = &self.sk.s;
        let s2 = s.mul(s, self.ntt);
        
        // Compute inner = d0 + d1*s + d2*s²
        let d1_s = d1.mul(s, self.ntt);
        let d2_s2 = d2.mul(&s2, self.ntt);
        let inner = d0.add(&d1_s, self.ntt).add(&d2_s2, self.ntt);
        
        // Decode using t²/q² scaling
        self.encoder.decode_degree2(&inner)
    }
    
    /// Decrypt vector
    pub fn decrypt_vector(&self, ct: &Ciphertext, len: usize) -> Vec<u64> {
        let decrypted = self.decrypt_raw(ct);
        self.encoder.decode_vector(&decrypted, len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeySet;
    
    fn setup() -> (FHEConfig, NTTEngine, KeySet, ShadowHarvester, BFVEncoder) {
        let config = FHEConfig::light();
        let ntt = NTTEngine::new(config.q, config.n);
        let mut harvester = ShadowHarvester::with_seed(42);
        let keys = KeySet::generate(&config, &ntt, &mut harvester);
        let encoder = BFVEncoder::new(&config);
        (config, ntt, keys, harvester, encoder)
    }
    
    #[test]
    fn test_encode_decode() {
        let config = FHEConfig::light();
        let encoder = BFVEncoder::new(&config);
        
        for m in [0, 1, 100, config.t - 1] {
            let encoded = encoder.encode(m);
            let decoded = encoder.decode(&encoded);
            assert_eq!(decoded, m, "Encode/decode failed for m={}", m);
        }
    }
    
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (config, ntt, keys, mut harvester, encoder) = setup();
        
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
        
        // Test various messages (staying well within noise budget)
        for m in [0u64, 1, 10, 100, 500, 1000] {
            let ct = encryptor.encrypt(m, &mut harvester);
            let decrypted = decryptor.decrypt(&ct);
            assert_eq!(decrypted, m, "Encrypt/decrypt failed for m={}", m);
        }
    }
    
    #[test]
    fn test_encrypt_decrypt_random() {
        let (config, ntt, keys, mut harvester, encoder) = setup();
        
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
        
        for _ in 0..20 {
            let m = harvester.uniform(config.t / 2);  // Stay within safe range
            let ct = encryptor.encrypt(m, &mut harvester);
            let decrypted = decryptor.decrypt(&ct);
            assert_eq!(decrypted, m, "Random encrypt/decrypt failed");
        }
    }
    
    #[test]
    fn test_encrypt_deterministic() {
        let (config, ntt, keys, _, encoder) = setup();
        
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        
        let ct1 = encryptor.encrypt_seeded(42, 12345);
        let ct2 = encryptor.encrypt_seeded(42, 12345);
        
        assert_eq!(ct1.c0.coeffs, ct2.c0.coeffs);
        assert_eq!(ct1.c1.coeffs, ct2.c1.coeffs);
    }
    
    #[test]
    fn test_encrypt_benchmark() {
        let (config, ntt, keys, mut harvester, encoder) = setup();
        
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        
        let start = std::time::Instant::now();
        for i in 0..1000u64 {
            let _ = encryptor.encrypt(i % config.t, &mut harvester);
        }
        let elapsed = start.elapsed();
        
        println!("Encrypt x1000: {:?}", elapsed);
    }
}
