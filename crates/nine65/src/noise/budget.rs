//! Noise Budget Tracking Module
//!
//! Integer-based noise budget tracking for FHE operations.
//! Uses millibits (1000 millibits = 1 bit) for precision without floats.
//!
//! # QMNF Innovation: Integer Noise Tracking
//!
//! Standard FHE libraries use floating-point for noise estimation:
//! ```ignore
//! noise_bits = log2(noise_magnitude)  // FLOAT!
//! ```
//!
//! QMNF uses exact integer arithmetic in millibits:
//! ```ignore
//! noise_millibits = integer_log2_scaled(noise_magnitude, 1000)
//! ```
//!
//! This prevents drift in noise estimates over deep circuits.

use crate::params::FHEConfig;

/// Noise budget in millibits (1000 millibits = 1 bit)
/// 
/// Tracks remaining noise budget through FHE operations.
/// When budget reaches 0, decryption will fail.
#[derive(Clone, Debug)]
pub struct NoiseBudget {
    /// Remaining budget in millibits
    remaining_mb: i64,
    /// Initial budget in millibits
    initial_mb: i64,
    /// Operations log (for debugging)
    operations: Vec<NoiseOperation>,
}

/// Record of a noise-consuming operation
#[derive(Clone, Debug)]
pub struct NoiseOperation {
    /// Operation type
    pub op_type: NoiseOpType,
    /// Noise cost in millibits
    pub cost_mb: i64,
    /// Budget after operation
    pub remaining_mb: i64,
}

/// Types of FHE operations
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum NoiseOpType {
    /// Fresh encryption
    Encrypt,
    /// Homomorphic addition (ct + ct)
    Add,
    /// Addition with plaintext (ct + pt)
    AddPlain,
    /// Multiplication with plaintext (ct × pt)
    MulPlain,
    /// Ciphertext multiplication (ct × ct)
    MulCt,
    /// Relinearization after multiplication
    Relin,
    /// Modulus switching / rescaling
    Rescale,
}

/// Error when noise budget is exhausted
#[derive(Debug, Clone)]
pub struct NoiseExhausted {
    /// How much budget was needed
    pub required_mb: i64,
    /// How much was available
    pub available_mb: i64,
    /// Total operations performed
    pub operation_count: usize,
    /// Last operation attempted
    pub last_op: NoiseOpType,
}

impl std::fmt::Display for NoiseExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Noise budget exhausted: needed {} millibits, had {} (after {} ops)",
               self.required_mb, self.available_mb, self.operation_count)
    }
}

impl std::error::Error for NoiseExhausted {}

impl NoiseBudget {
    /// Create noise budget from FHE parameters
    ///
    /// Budget is calculated as: log2(Δ) - log2(initial_noise)
    /// where Δ = q/t is the scaling factor and initial_noise depends on η
    pub fn from_config(config: &FHEConfig) -> Self {
        let delta = config.delta();
        
        // log2(Δ) in millibits
        let delta_bits = if delta > 0 { 64 - delta.leading_zeros() } else { 0 };
        let delta_mb = (delta_bits as i64) * 1000;
        
        // Initial noise estimate: η × √N × constant
        // In millibits: approximately (log2(η) + log2(N)/2 + 3) × 1000
        let eta_bits = if config.eta > 0 { 64 - (config.eta as u64).leading_zeros() } else { 1 };
        let n_bits = config.n.trailing_zeros();  // log2(N) since N is power of 2
        let initial_noise_mb = ((eta_bits as i64) + (n_bits as i64 / 2) + 3) * 1000;
        
        let budget_mb = delta_mb.saturating_sub(initial_noise_mb);
        
        Self {
            remaining_mb: budget_mb,
            initial_mb: budget_mb,
            operations: Vec::new(),
        }
    }
    
    /// Create with specific initial budget (for testing)
    pub fn with_budget_bits(bits: i64) -> Self {
        let mb = bits * 1000;
        Self {
            remaining_mb: mb,
            initial_mb: mb,
            operations: Vec::new(),
        }
    }
    
    /// Consume noise budget for an operation
    ///
    /// Returns `Ok(remaining)` if budget sufficient, `Err(NoiseExhausted)` otherwise.
    pub fn consume(&mut self, op_type: NoiseOpType, cost_mb: i64) -> Result<i64, NoiseExhausted> {
        if self.remaining_mb < cost_mb {
            return Err(NoiseExhausted {
                required_mb: cost_mb,
                available_mb: self.remaining_mb,
                operation_count: self.operations.len(),
                last_op: op_type,
            });
        }
        
        self.remaining_mb -= cost_mb;
        
        self.operations.push(NoiseOperation {
            op_type,
            cost_mb,
            remaining_mb: self.remaining_mb,
        });
        
        Ok(self.remaining_mb)
    }
    
    /// Estimate cost of encryption
    pub fn encrypt_cost(config: &FHEConfig) -> i64 {
        // Encryption adds error e with distribution CBD(η)
        // Cost ≈ log2(η × √N) × 1000 millibits
        let eta_bits = 64 - (config.eta as u64).leading_zeros();
        let n_bits = config.n.trailing_zeros();
        ((eta_bits as i64) + (n_bits as i64 / 2)) * 1000
    }
    
    /// Estimate cost of homomorphic addition
    pub fn add_cost() -> i64 {
        // Addition roughly doubles noise, cost ≈ 1 bit = 1000 millibits
        1000
    }
    
    /// Estimate cost of plaintext addition
    pub fn add_plain_cost() -> i64 {
        // Minimal noise increase
        100
    }
    
    /// Estimate cost of plaintext multiplication
    pub fn mul_plain_cost(config: &FHEConfig) -> i64 {
        // Noise multiplied by plaintext coefficient bound
        // Cost ≈ log2(t) × 1000 millibits
        let t_bits = 64 - config.t.leading_zeros();
        (t_bits as i64) * 1000
    }
    
    /// Estimate cost of ciphertext multiplication
    pub fn mul_ct_cost(config: &FHEConfig) -> i64 {
        // Most expensive operation
        // Cost ≈ (log2(t) + log2(N) + log2(η)) × 1000
        let t_bits = 64 - config.t.leading_zeros();
        let n_bits = config.n.trailing_zeros();
        let eta_bits = 64 - (config.eta as u64).leading_zeros();
        ((t_bits as i64) + (n_bits as i64) + (eta_bits as i64)) * 1000
    }
    
    /// Estimate cost of relinearization
    pub fn relin_cost(config: &FHEConfig) -> i64 {
        // Depends on decomposition base
        // Typically adds log2(N) bits of noise
        let n_bits = config.n.trailing_zeros();
        (n_bits as i64) * 1000
    }
    
    /// Get remaining budget in millibits
    pub fn remaining_millibits(&self) -> i64 {
        self.remaining_mb
    }
    
    /// Get remaining budget in bits (approximate)
    pub fn remaining_bits(&self) -> f64 {
        self.remaining_mb as f64 / 1000.0
    }
    
    /// Get initial budget in bits
    pub fn initial_bits(&self) -> f64 {
        self.initial_mb as f64 / 1000.0
    }
    
    /// Check if operation can be performed
    pub fn can_perform(&self, cost_mb: i64) -> bool {
        self.remaining_mb >= cost_mb
    }
    
    /// Estimate how many more multiplications can be performed
    pub fn remaining_multiplications(&self, config: &FHEConfig) -> usize {
        let mul_cost = Self::mul_ct_cost(config) + Self::relin_cost(config);
        if mul_cost <= 0 { return usize::MAX; }
        (self.remaining_mb / mul_cost) as usize
    }
    
    /// Get operation history
    pub fn operations(&self) -> &[NoiseOperation] {
        &self.operations
    }
    
    /// Get summary statistics
    pub fn summary(&self) -> String {
        let used = self.initial_mb - self.remaining_mb;
        let remaining_bits = self.remaining_bits();
        let initial_bits = self.initial_bits();
        
        format!(
            "Noise Budget: {:.1}/{:.1} bits remaining ({:.1}% used, {} ops)",
            remaining_bits,
            initial_bits,
            100.0 * used as f64 / self.initial_mb as f64,
            self.operations.len()
        )
    }
}

impl std::fmt::Display for NoiseBudget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.summary())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_noise_budget_creation() {
        let config = FHEConfig::light();
        let budget = NoiseBudget::from_config(&config);
        
        println!("Light config budget: {}", budget);
        assert!(budget.remaining_bits() > 0.0, "Should have positive budget");
    }
    
    #[test]
    fn test_noise_budget_consumption() {
        let config = FHEConfig::light();
        let mut budget = NoiseBudget::from_config(&config);
        
        let initial = budget.remaining_bits();
        
        // Perform addition
        budget.consume(NoiseOpType::Add, NoiseBudget::add_cost()).unwrap();
        
        assert!(budget.remaining_bits() < initial, "Budget should decrease");
        assert_eq!(budget.operations().len(), 1);
    }
    
    #[test]
    fn test_noise_budget_exhaustion() {
        let mut budget = NoiseBudget::with_budget_bits(5);  // Only 5 bits
        
        // Try expensive operation
        let result = budget.consume(NoiseOpType::MulCt, 10000);  // 10 bits needed
        
        assert!(result.is_err(), "Should fail when budget exhausted");
        if let Err(e) = result {
            assert_eq!(e.last_op, NoiseOpType::MulCt);
        }
    }
    
    #[test]
    fn test_noise_budget_tracking() {
        // Use explicit budget for predictable test behavior
        let mut budget = NoiseBudget::with_budget_bits(50);  // 50 bits = plenty of room
        
        println!("Initial: {}", budget);
        
        // Simulate operations with fixed costs
        let r1 = budget.consume(NoiseOpType::Encrypt, 5000);  // 5 bits
        println!("After encrypt: {} (result: {:?})", budget, r1.is_ok());
        assert!(r1.is_ok(), "Encrypt should succeed");
        
        let r2 = budget.consume(NoiseOpType::Add, 1000);  // 1 bit
        println!("After add: {} (result: {:?})", budget, r2.is_ok());
        assert!(r2.is_ok(), "Add should succeed");
        
        let r3 = budget.consume(NoiseOpType::MulPlain, 10000);  // 10 bits
        println!("After mul_plain: {} (result: {:?})", budget, r3.is_ok());
        assert!(r3.is_ok(), "MulPlain should succeed");
        
        // Check all operations were recorded
        assert_eq!(budget.operations().len(), 3);
        
        // Verify budget decreased correctly
        assert_eq!(budget.remaining_millibits(), 50000 - 5000 - 1000 - 10000);
    }
    
    #[test]
    fn test_remaining_multiplications() {
        let config = FHEConfig::light_mul();
        let budget = NoiseBudget::from_config(&config);
        
        let remaining_muls = budget.remaining_multiplications(&config);
        println!("Remaining multiplications for light_mul: {}", remaining_muls);
    }
    
    #[test]
    fn test_he_standard_budget() {
        let config = FHEConfig::he_standard_128();
        let budget = NoiseBudget::from_config(&config);
        
        println!("HE Standard 128 budget: {}", budget);
        println!("Remaining multiplications: {}", budget.remaining_multiplications(&config));
        
        assert!(budget.remaining_bits() > 0.0, "HE Standard should have positive budget");
    }
}
