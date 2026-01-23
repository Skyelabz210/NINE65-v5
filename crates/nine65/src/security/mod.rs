//! Security Estimation Module
//!
//! Provides LWE-based security estimates for QMNF FHE parameters.
//! Based on HomomorphicEncryption.org Security Standard v1.1 tables.
//!
//! For precise estimates, run the external LWE Estimator:
//! `sage -python scripts/lwe_estimate.py`

use crate::params::FHEConfig;

/// LWE parameters for security estimation
#[derive(Debug, Clone)]
pub struct LWEParams {
    /// Ring dimension
    pub n: usize,
    /// Log base-2 of modulus
    pub log_q: u32,
    /// Error distribution parameter (σ for Gaussian, η for CBD)
    pub sigma: f64,
    /// Error distribution type
    pub error_type: ErrorDistribution,
}

/// Type of error distribution
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorDistribution {
    /// Discrete Gaussian with standard deviation σ
    DiscreteGaussian,
    /// Centered Binomial Distribution with parameter η
    CBD,
    /// Ternary uniform distribution
    Ternary,
}

/// Security estimate result
#[derive(Debug, Clone)]
pub struct SecurityEstimate {
    /// Classical security level in bits
    pub classical_bits: u32,
    /// Quantum security level in bits (rough estimate)
    pub quantum_bits: u32,
    /// Best known attack
    pub best_attack: String,
    /// Confidence level of estimate
    pub confidence: ConfidenceLevel,
    /// N/log(q) ratio (key security indicator)
    pub ratio: f64,
}

/// Confidence level of security estimate
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfidenceLevel {
    /// Quick heuristic estimate
    Rough,
    /// Based on HE Standard tables
    Standard,
    /// Full lattice-estimator run
    Precise,
}

impl LWEParams {
    /// Extract LWE parameters from FHE config
    pub fn from_config(config: &FHEConfig) -> Self {
        let log_q = 64 - config.q.leading_zeros();
        
        // CBD(η) has σ ≈ √(η/2)
        let sigma = (config.eta as f64 / 2.0).sqrt();
        
        Self {
            n: config.n,
            log_q,
            sigma,
            error_type: ErrorDistribution::CBD,
        }
    }
    
    /// Create with custom parameters
    pub fn new(n: usize, log_q: u32, sigma: f64) -> Self {
        Self {
            n,
            log_q,
            sigma,
            error_type: ErrorDistribution::DiscreteGaussian,
        }
    }
    
    /// Get N/log(q) ratio (key security indicator)
    pub fn ratio(&self) -> f64 {
        self.n as f64 / self.log_q as f64
    }
    
    /// Estimate security using HE Standard v1.1 Table 3
    ///
    /// This provides conservative estimates based on the published
    /// Homomorphic Encryption Security Standard.
    ///
    /// # Reference
    /// Martin Albrecht et al., "Homomorphic Encryption Standard v1.1"
    /// HomomorphicEncryption.org, 2018
    pub fn he_standard_estimate(&self) -> SecurityEstimate {
        let ratio = self.ratio();
        
        // HE Standard Table 3 thresholds (conservative)
        // These are N/log(q) ratios for different security levels
        let (classical_bits, best_attack) = if ratio > 50.0 {
            (256, "BKZ/sieving theoretical limit")
        } else if ratio > 38.0 {
            (192, "BKZ with progressive sieving")
        } else if ratio > 28.0 {
            (128, "BKZ with lattice sieving")
        } else if ratio > 18.0 {
            (96, "BKZ with enumeration")
        } else if ratio > 12.0 {
            (80, "Hybrid lattice attack")
        } else {
            (64, "Direct lattice attack")
        };
        
        // Quantum security roughly 2/3 of classical for lattice problems
        // (Grover doesn't help much for lattice)
        let quantum_bits = (classical_bits * 2) / 3;
        
        SecurityEstimate {
            classical_bits,
            quantum_bits,
            best_attack: best_attack.to_string(),
            confidence: ConfidenceLevel::Standard,
            ratio,
        }
    }
    
    /// Quick heuristic estimate
    ///
    /// Faster but less accurate than HE Standard lookup.
    pub fn quick_estimate(&self) -> SecurityEstimate {
        // Rule of thumb: security ≈ 2.6 × n / log(q)
        let raw_estimate = 2.6 * self.n as f64 / self.log_q as f64;
        
        // Round to standard levels
        let classical_bits = if raw_estimate >= 240.0 {
            256
        } else if raw_estimate >= 180.0 {
            192
        } else if raw_estimate >= 120.0 {
            128
        } else if raw_estimate >= 90.0 {
            96
        } else if raw_estimate >= 75.0 {
            80
        } else {
            64
        };
        
        let quantum_bits = (classical_bits * 2) / 3;
        
        SecurityEstimate {
            classical_bits,
            quantum_bits,
            best_attack: "Heuristic estimate".to_string(),
            confidence: ConfidenceLevel::Rough,
            ratio: self.ratio(),
        }
    }
    
    /// Check if parameters meet HE Standard for target security
    pub fn meets_he_standard(&self, target_bits: u32) -> bool {
        // HE Standard Table 3 minimum N/log(q) ratios
        let required_ratio = match target_bits {
            256 => 50.0,
            192 => 38.0,
            128 => 28.0,
            96 => 18.0,
            80 => 12.0,
            _ => return false,
        };
        
        self.ratio() >= required_ratio
    }
    
    /// Get maximum log(q) for given N at target security
    pub fn max_log_q_for_security(n: usize, target_bits: u32) -> u32 {
        let required_ratio = match target_bits {
            256 => 50.0,
            192 => 38.0,
            128 => 28.0,
            96 => 18.0,
            80 => 12.0,
            _ => 10.0,
        };
        
        (n as f64 / required_ratio).floor() as u32
    }
    
    /// Generate security documentation
    pub fn security_rationale(&self, config_name: &str) -> String {
        let estimate = self.he_standard_estimate();
        
        format!(
            r#"Security Rationale for '{}'
================================

Parameters:
  Ring dimension N: {}
  Modulus bits log(q): {}
  Error parameter σ: {:.3}
  Error distribution: {:?}

Security Analysis:
  N/log(q) ratio: {:.1}
  
  HE Standard Estimate:
    Classical security: {} bits
    Quantum security: ~{} bits
    Best known attack: {}
    Confidence: {:?}

Verification:
  □ Run `sage -python scripts/lwe_estimate.py` for precise estimate
  □ Compare against HE Standard Table 3
  □ Verify σ ≥ 3.2 for security proofs

References:
  [1] HomomorphicEncryption.org Security Standard v1.1 (2018)
  [2] Albrecht et al., "On the concrete hardness of Learning with Errors"
"#,
            config_name,
            self.n,
            self.log_q,
            self.sigma,
            self.error_type,
            self.ratio(),
            estimate.classical_bits,
            estimate.quantum_bits,
            estimate.best_attack,
            estimate.confidence,
        )
    }
}

impl SecurityEstimate {
    /// Check if meets minimum security level
    pub fn meets_minimum(&self, min_classical: u32, min_quantum: u32) -> bool {
        self.classical_bits >= min_classical && self.quantum_bits >= min_quantum
    }
    
    /// Human-readable security level name
    pub fn level_name(&self) -> &'static str {
        match self.classical_bits {
            256.. => "Ultra-High (256-bit)",
            192..=255 => "Very High (192-bit)",
            128..=191 => "High (128-bit)",
            96..=127 => "Medium (96-bit)",
            80..=95 => "Standard (80-bit)",
            _ => "Low",
        }
    }
}

impl std::fmt::Display for SecurityEstimate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {} bits classical, ~{} bits quantum (ratio: {:.1})",
               self.level_name(),
               self.classical_bits,
               self.quantum_bits,
               self.ratio)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_lwe_params_from_config() {
        let config = FHEConfig::light();
        let params = LWEParams::from_config(&config);
        
        assert_eq!(params.n, 1024);
        assert!(params.log_q > 0);
        assert!(params.sigma > 0.0);
        
        println!("Light config: N={}, log(q)={}, σ={:.3}",
                 params.n, params.log_q, params.sigma);
    }
    
    #[test]
    fn test_he_standard_estimate() {
        let config = FHEConfig::he_standard_128();
        let params = LWEParams::from_config(&config);
        let estimate = params.he_standard_estimate();
        
        println!("HE Standard 128 estimate: {}", estimate);
        println!("{}", params.security_rationale("he_standard_128"));
        
        assert!(estimate.classical_bits >= 128,
                "HE Standard config should provide 128-bit security");
        assert!(params.meets_he_standard(128),
                "Should meet HE Standard for 128-bit");
    }
    
    #[test]
    fn test_security_levels() {
        let test_cases = [
            (1024, 30, 80),   // Light config
            (2048, 30, 128),  // HE Standard 128
            (2048, 54, 128),  // HE Standard max q
            (4096, 60, 128),  // Standard BFV
            (8192, 218, 128), // Deep circuits
        ];
        
        for (n, log_q, expected_min) in test_cases {
            let params = LWEParams::new(n, log_q, 3.2);
            let estimate = params.he_standard_estimate();
            
            println!("N={}, log(q)={}: {} bits (ratio {:.1})",
                     n, log_q, estimate.classical_bits, estimate.ratio);
            
            assert!(estimate.classical_bits >= expected_min,
                    "N={}, log(q)={} should have >= {} bits security",
                    n, log_q, expected_min);
        }
    }
    
    #[test]
    fn test_max_log_q() {
        let n = 2048;
        let max_128 = LWEParams::max_log_q_for_security(n, 128);
        let max_192 = LWEParams::max_log_q_for_security(n, 192);
        
        println!("N={}: max log(q) for 128-bit = {}, for 192-bit = {}",
                 n, max_128, max_192);
        
        assert!(max_128 > max_192, "Higher security requires smaller q");
        assert!(max_128 >= 54, "Should allow at least 54-bit q for 128-bit");
    }
    
    #[test]
    fn test_all_configs_security() {
        let configs = [
            ("light", FHEConfig::light()),
            ("he_standard_128", FHEConfig::he_standard_128()),
            ("standard_128", FHEConfig::standard_128()),
            ("high_192", FHEConfig::high_192()),
        ];
        
        for (name, config) in configs {
            let params = LWEParams::from_config(&config);
            let estimate = params.he_standard_estimate();
            
            println!("{}: {} (N={}, log(q)={})",
                     name, estimate, config.n, params.log_q);
            
            // All configs should have at least 80-bit security
            assert!(estimate.classical_bits >= 80,
                    "{} has insufficient security", name);
        }
    }
}
