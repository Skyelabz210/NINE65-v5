//! FHE Configuration - Parameter Sets for Various Security Levels
//!
//! QMNF provides pre-validated parameter sets:
//! - light: Testing ONLY (80-bit security) - NOT FOR PRODUCTION
//! - standard_128: Production (128-bit security)
//! - high_192: High security (192-bit security)
//! - deep_128: Deep circuits (128-bit, larger N)
//! - batched: SIMD operations (128-bit, small t)
//!
//! For production deployment, use the `production` module.
//!
//! SECURITY: Always validate parameters before use to prevent
//! the Hidden Orbital Problem. Use the `validation` module.

pub mod primes;
pub mod production;
pub mod validation;

pub use primes::*;
pub use validation::{validate_params, assert_params_valid, ParameterValidator, ValidationResult};

/// FHE Configuration Parameters
#[derive(Clone, Debug)]
pub struct FHEConfig {
    /// Polynomial degree (power of 2)
    pub n: usize,
    /// Ciphertext modulus primes
    pub primes: Vec<u64>,
    /// Primary ciphertext modulus (product or first prime)
    pub q: u64,
    /// Plaintext modulus
    pub t: u64,
    /// Noise parameter (CBD eta)
    pub eta: usize,
    /// Security level in bits
    pub security_bits: usize,
    /// Name of this parameter set
    pub name: &'static str,
}

impl FHEConfig {
    /// Light configuration for testing (80-bit security)
    /// Small parameters, fast operations
    /// NOTE: Single-modulus, limited to add/mul_plain only
    pub fn light() -> Self {
        Self {
            n: 1024,
            primes: vec![998244353],
            q: 998244353,
            t: 2053,  // Carefully chosen to avoid encode/decode precision issues
            eta: 2,
            security_bits: 80,
            name: "light",
        }
    }
    
    /// Configuration for ct×ct multiplication using large single modulus
    /// Uses 60-bit prime so Δ² fits without overflow
    pub fn large_single() -> Self {
        // Use a 60-bit NTT-compatible prime
        // q must satisfy: q ≡ 1 (mod 2N) for NTT
        // For N=4096: q ≡ 1 (mod 8192)
        // 1152921504606846593 = 2^60 + 8193 is prime and ≡ 1 (mod 8192)
        let q: u64 = 1152921504606846593;
        let _t: u64 = 65537;  // Standard plaintext modulus
        
        // Δ = q/t ≈ 17.6 trillion
        // Δ² ≈ 3.1 × 10^26 which is > q, so this still overflows
        
        // Need smaller t to make Δ smaller
        // If t = q/1000, then Δ = 1000, Δ² = 1M << q ✓
        // Let's use t = 2^20 ≈ 1M, Δ ≈ 1T, Δ² ≈ 10^24 which is still huge
        
        // Actually for Δ² < q we need Δ < √q ≈ 10^9
        // So t > q/10^9 ≈ 10^9
        // Use t = 10^9 + small adjustment for NTT compatibility
        
        // Simpler approach: use smaller N to allow larger t
        // For testing, use N=1024 and t that gives Δ < √q
        
        Self {
            n: 4096,
            primes: vec![q],
            q,
            t: 1099511627777,  // ~2^40, gives Δ ≈ 2^20
            eta: 3,
            security_bits: 128,
            name: "large_single",
        }
    }
    
    /// Configuration for ct×ct testing with small Δ to avoid Δ² overflow
    /// Uses large t to keep Δ small enough that Δ² < q
    /// WARNING: Has only ~1 bit noise budget - use light_rns for real work
    pub fn light_mul() -> Self {
        // For single-modulus ct×ct: need Δ² < q (so tensor product doesn't overflow)
        // With t=500000: Δ ≈ 1996, Δ² ≈ 4M < q ✓
        // BUT: noise budget = log2(Δ) - initial_noise ≈ 11 - 10 = 1 bit!
        Self {
            n: 1024,
            primes: vec![998244353],
            q: 998244353,
            t: 500000,  // Large t gives small Δ
            eta: 2,
            security_bits: 80,
            name: "light_mul",
        }
    }

    /// Light RNS configuration for ct×ct multiplication with proper noise budget
    ///
    /// Uses THREE 30-bit NTT-compatible primes for RNS multiplication:
    /// - Effective Q = q1 × q2 × q3 ≈ 7.4 × 10^26 (~90 bits)
    /// - Each channel: Δ_i = qi/t ≈ 15231, Δ_i² ≈ 232M < qi ✓
    /// - Noise budget: log2(Q/t) - initial ≈ 74 bits
    /// - Required: Q > N × q² for safe CRT reconstruction
    ///   - N × q² = 1024 × (10^9)² ≈ 10^21 (~70 bits)
    ///   - Q ≈ 7.4 × 10^26 (~90 bits) > 10^21 ✓
    /// - Supports 5+ levels of CT×CT multiplication
    ///
    /// This is the RECOMMENDED light config for multiplication testing.
    pub fn light_rns() -> Self {
        Self {
            n: 1024,
            // Three 30-bit NTT primes: Q ≈ 7.4 × 10^26 (~90 bits)
            // This ensures Q > N × q² for safe CRT reconstruction
            primes: vec![998244353, 985661441, 754974721],
            q: 998244353,  // Primary modulus for output
            t: 65537,      // Standard plaintext modulus
            eta: 2,
            security_bits: 80,
            name: "light_rns",
        }
    }

    /// QMNF Exact RNS configuration for ct×ct multiplication
    ///
    /// Uses the QMNF exact multiplication approach from ct_mul_exact:
    /// - Single 30-bit modulus q = 998244353
    /// - Large t = 500000 → small Δ ≈ 1996
    /// - Δ² ≈ 4M << M×A (92-bit reconstruction capacity)
    /// - K-Elimination enables exact rescaling (no float)
    ///
    /// Key constraint: Δ² < 2^92 (M×A capacity)
    /// With Δ ≈ 2000, Δ² ≈ 4M << 2^92 ✓
    ///
    /// Trade-off: Smaller plaintext space (t=500000 vs t=65537)
    /// but exact arithmetic and guaranteed correct results.
    ///
    /// This is the config that matches the QMNF papers' exact approach.
    pub fn light_exact() -> Self {
        Self {
            n: 1024,
            primes: vec![998244353],  // Single 30-bit prime
            q: 998244353,
            t: 500000,  // Large t → small Δ → Δ² fits in reconstruction capacity
            eta: 2,
            security_bits: 80,
            name: "light_exact",
        }
    }

    /// QMNF Exact RNS with 2 primes using K-Elimination for rescaling
    ///
    /// Uses the QMNF K-Elimination approach:
    /// - Main modulus M = Q = product of primes ≈ 9.84e17 (~60 bits)
    /// - Anchor modulus A ≈ 4.6e18 (~62 bits) from ExactDivider
    /// - Reconstruction capacity M×A ≈ 2^122 (way more than needed)
    ///
    /// Critical constraint: Δ² < M×A (K-Elimination reconstruction limit)
    /// - Need Δ < 2^61 → need t > Q/2^61 ≈ 1 (any t works!)
    ///
    /// Practical choice: t = 65537 (standard plaintext modulus)
    /// - Δ = Q/t ≈ 1.5e13 ≈ 2^44
    /// - Δ² ≈ 2^88 < M×A ≈ 2^122 ✓
    /// - Noise budget: log2(Δ) - initial ≈ 44 - 12 ≈ 32 bits (plenty!)
    ///
    /// NOTE: This config requires K-Elimination rescaling in RNSFHEContext.
    /// Standard Bajard rescaling will fail because Δ² > Q.
    pub fn light_rns_exact() -> Self {
        Self {
            n: 1024,
            primes: vec![998244353, 985661441],  // Two 30-bit primes: Q ≈ 2^60
            q: 998244353,
            t: 65537,  // Standard t → Δ ≈ 2^44, Δ² ≈ 2^88 < M×A ≈ 2^122 ✓
            eta: 2,
            security_bits: 80,
            name: "light_rns_exact",
        }
    }

    /// Check if this config supports RNS-based ct×ct multiplication
    pub fn supports_rns_mul(&self) -> bool {
        self.primes.len() >= 2
    }

    /// Get the effective modulus product Q for RNS configs
    pub fn rns_product(&self) -> u128 {
        self.primes.iter().fold(1u128, |acc, &p| acc * p as u128)
    }

    /// Get noise budget in bits for RNS multiplication
    /// This accounts for the larger effective modulus from multiple primes
    pub fn rns_noise_budget(&self) -> f64 {
        if self.primes.len() < 2 {
            return self.noise_budget() as f64;
        }

        // With RNS, effective Q = product of all primes
        let q_product = self.rns_product();
        let delta_effective = q_product / self.t as u128;
        let delta_bits = 128 - delta_effective.leading_zeros();

        // Initial noise estimate
        let eta_bits = self.eta as u32 + 1;  // log2(2*eta)
        let n_bits = (self.n as f64).log2() / 2.0;  // log2(sqrt(n))
        let initial_noise = eta_bits as f64 + n_bits + 3.0;  // safety margin

        (delta_bits as f64) - initial_noise
    }
    
    /// Standard 128-bit security configuration
    ///
    /// Uses 3 NTT-friendly primes for RNS multiplication.
    /// RNS capacity Q ≈ 10^27 >> N × q² ≈ 4 × 10^21 (tensor product bound)
    pub fn standard_128() -> Self {
        Self {
            n: 4096,
            // 3 primes required for RNS multiplication: Q > N × q²
            // 998244353 × 985661441 × 754974721 ≈ 7.4 × 10^26
            // This ensures tensor product coefficients (up to ~4 × 10^21) don't overflow
            primes: vec![998244353, 985661441, 754974721],
            q: 998244353,  // Primary modulus
            t: 65537,
            eta: 3,
            security_bits: 128,
            name: "standard_128",
        }
    }
    
    /// High 192-bit security configuration
    pub fn high_192() -> Self {
        Self {
            n: 8192,
            primes: vec![998244353, 985661441, 754974721],
            q: 998244353,
            t: 65537,
            eta: 3,
            security_bits: 192,
            name: "high_192",
        }
    }
    
    /// Deep circuit configuration (larger N for more noise budget)
    pub fn deep_128() -> Self {
        Self {
            n: 16384,
            primes: vec![998244353, 985661441, 754974721, 469762049],
            q: 998244353,
            t: 65537,
            eta: 3,
            security_bits: 128,
            name: "deep_128",
        }
    }
    
    /// Batched/SIMD configuration (small t for slot packing)
    ///
    /// Uses 3 primes for RNS multiplication capacity.
    pub fn batched() -> Self {
        Self {
            n: 4096,
            primes: vec![998244353, 985661441, 754974721],
            q: 998244353,
            t: 257,  // Small prime for efficient batching
            eta: 3,
            security_bits: 128,
            name: "batched",
        }
    }
    
    /// HE Standard 128-bit Compliant Configuration
    /// 
    /// Meets HomomorphicEncryption.org Security Standard v1.1:
    /// - N = 2048 (minimum for 128-bit security)
    /// - log(q) ≤ 54 bits (we use 30-bit prime)
    /// - N/log(q) ratio ≈ 68 (well above 38 threshold)
    /// 
    /// This is the **recommended production configuration** for applications
    /// requiring formal compliance with published standards.
    /// 
    /// # Security Analysis
    /// 
    /// | Parameter | Value | Requirement | Status |
    /// |-----------|-------|-------------|--------|
    /// | N | 2048 | ≥ 2048 | ✓ |
    /// | log(q) | 30 | ≤ 54 | ✓ |
    /// | N/log(q) | 68.3 | > 38 | ✓ |
    /// | Security | 128-bit | 128-bit | ✓ |
    pub fn he_standard_128() -> Self {
        // Validate at construction time
        let config = Self {
            n: 2048,
            primes: vec![998244353],  // 30-bit NTT-friendly prime
            q: 998244353,
            t: 65537,  // Standard plaintext modulus (Fermat prime F4)
            eta: 3,
            security_bits: 128,
            name: "he_standard_128",
        };
        
        // Verify orbital bounds
        let result = validate_params(config.n, config.q, config.t);
        debug_assert!(result.orbital_safe, 
                     "he_standard_128 config fails orbital bounds check");
        
        config
    }
    
    /// HE Standard 128-bit with larger plaintext space
    /// 
    /// Same security as `he_standard_128` but with smaller Δ for
    /// more noise budget. Trade-off: smaller maximum plaintext values.
    pub fn he_standard_128_deep() -> Self {
        Self {
            n: 2048,
            primes: vec![998244353],
            q: 998244353,
            t: 4096,  // Larger t = smaller Δ = more noise budget
            eta: 3,
            security_bits: 128,
            name: "he_standard_128_deep",
        }
    }
    
    /// Check if this config supports single-modulus ct×ct multiplication
    /// Returns (supported, max_product) where max_product is the largest
    /// m1×m2 value that can be computed without overflow
    pub fn supports_single_mod_mul(&self) -> (bool, u64) {
        let delta = self.delta();
        let delta_squared = (delta as u128) * (delta as u128);
        
        if delta_squared >= self.q as u128 {
            // Δ² > q: single-mod ct×ct will overflow
            // Return max product that keeps Δ² × product < q
            let max = self.q as u128 / delta_squared;
            (false, max.min(u64::MAX as u128) as u64)
        } else {
            // Δ² < q: can do ct×ct with products up to q/Δ²
            let max = self.q as u128 / delta_squared;
            (true, max.min(u64::MAX as u128) as u64)
        }
    }
    
    /// Custom configuration with validation
    pub fn custom(
        n: usize,
        primes: Vec<u64>,
        t: u64,
        eta: usize,
    ) -> Result<Self, &'static str> {
        // Validate n is power of 2
        if !n.is_power_of_two() {
            return Err("N must be a power of 2");
        }
        
        if n < 512 {
            return Err("N must be at least 512 for security");
        }
        
        // Validate primes
        if primes.is_empty() {
            return Err("Need at least one prime");
        }
        
        for &p in &primes {
            if !is_prime(p) {
                return Err("All moduli must be prime");
            }
            if !is_ntt_compatible(p, n) {
                return Err("Primes must be NTT-compatible (q ≡ 1 mod 2N)");
            }
        }
        
        // Validate t
        if t < 2 {
            return Err("Plaintext modulus must be at least 2");
        }
        
        // Estimate security
        let security_bits = estimate_security(n, primes[0]);
        
        Ok(Self {
            n,
            primes: primes.clone(),
            q: primes[0],
            t,
            eta,
            security_bits,
            name: "custom",
        })
    }
    
    /// Get the scaling factor Δ = floor(q/t)
    pub fn delta(&self) -> u64 {
        self.q / self.t
    }
    
    /// Estimate noise budget in bits
    pub fn noise_budget(&self) -> usize {
        // Approximate: log2(Δ) - log2(initial_noise)
        let delta_bits = 64 - self.delta().leading_zeros();
        let noise_bits = (self.eta as u32 * 2) + (self.n.trailing_zeros());
        if delta_bits > noise_bits {
            (delta_bits - noise_bits) as usize
        } else {
            0
        }
    }
    
    /// Estimate multiplicative depth
    pub fn estimated_depth(&self) -> usize {
        // Very rough estimate: noise budget / bits_per_mul
        let budget = self.noise_budget();
        let bits_per_mul = (64 - self.t.leading_zeros()) as usize + 5;
        if bits_per_mul > 0 {
            budget / bits_per_mul
        } else {
            0
        }
    }
}

/// Estimate security level based on LWE hardness
fn estimate_security(n: usize, q: u64) -> usize {
    // Simplified estimate based on n and log2(q)
    let log_q = 64 - q.leading_zeros();
    let ratio = n as f64 / log_q as f64;
    
    if ratio > 50.0 {
        192
    } else if ratio > 30.0 {
        128
    } else if ratio > 20.0 {
        80
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_all_configs_valid() {
        let configs = [
            FHEConfig::light(),
            FHEConfig::light_mul(),
            FHEConfig::light_rns(),
            FHEConfig::standard_128(),
            FHEConfig::high_192(),
            FHEConfig::deep_128(),
            FHEConfig::batched(),
            FHEConfig::he_standard_128(),
            FHEConfig::he_standard_128_deep(),
        ];
        
        for config in configs {
            assert!(config.n.is_power_of_two(), "{} n not power of 2", config.name);
            assert!(!config.primes.is_empty(), "{} has no primes", config.name);
            assert!(config.t >= 2, "{} t too small", config.name);
            assert!(config.delta() > 0, "{} delta is 0", config.name);

            let rns_info = if config.supports_rns_mul() {
                format!("RNS Q={:.2e}, RNS budget={:.0}bits",
                        config.rns_product() as f64,
                        config.rns_noise_budget())
            } else {
                "single-mod".to_string()
            };

            println!("{}: N={}, q={}, t={}, Δ={}, budget={}bits, depth≈{}, {}",
                     config.name, config.n, config.q, config.t,
                     config.delta(), config.noise_budget(), config.estimated_depth(),
                     rns_info);
        }
    }
    
    #[test]
    fn test_he_standard_compliance() {
        let config = FHEConfig::he_standard_128();
        
        // HE Standard v1.1 Table 3 requirements for 128-bit classical security
        let log_q = 64 - config.q.leading_zeros();
        let he_max_log_q = 54;  // For N=2048
        
        assert!(config.n >= 2048, "N must be >= 2048 for 128-bit");
        assert!(log_q <= he_max_log_q, 
                "log(q)={} exceeds HE Standard max {} for N={}", 
                log_q, he_max_log_q, config.n);
        
        // Verify N/log(q) ratio (rough security indicator)
        let ratio = config.n as f64 / log_q as f64;
        assert!(ratio > 38.0, "N/log(q) ratio {} too low for 128-bit", ratio);
        
        // Verify orbital safety
        let result = validate_params(config.n, config.q, config.t);
        assert!(result.orbital_safe, "HE Standard config fails orbital bounds");
        assert!(result.he_standard_compliant, "HE Standard config not compliant");
        
        println!("HE Standard 128-bit Compliance:");
        println!("  N = {}", config.n);
        println!("  log(q) = {} (max {})", log_q, he_max_log_q);
        println!("  N/log(q) = {:.1} (need > 38)", ratio);
        println!("  Orbital safe: {}", result.orbital_safe);
        println!("  HE compliant: {}", result.he_standard_compliant);
    }
    
    #[test]
    fn test_custom_config() {
        let config = FHEConfig::custom(
            2048,
            vec![998244353],
            1024,
            2,
        ).expect("Should create valid config");
        
        assert_eq!(config.n, 2048);
        assert_eq!(config.t, 1024);
    }
    
    #[test]
    fn test_estimated_depth() {
        let light = FHEConfig::light();
        let deep = FHEConfig::deep_128();
        
        // Deep config should have more depth
        assert!(deep.estimated_depth() >= light.estimated_depth(),
                "Deep config should have >= depth");
    }
}
