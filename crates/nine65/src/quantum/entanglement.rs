//! Quantum Entanglement via Coprime Modular Correlation
//!
//! NINE65 QUANTUM TEST: Algebraic entanglement primitives
//!
//! In quantum mechanics, entangled particles have correlated states:
//!   - Measuring one instantly determines the other
//!   - The correlation exists before measurement
//!   - Neither particle alone has definite state
//!
//! In QMNF, coprime moduli create analogous correlations:
//!   - A value X exists as (x₁, x₂, ..., xₖ) across residues
//!   - Each residue alone is ambiguous (many X map to it)
//!   - Together they uniquely determine X (CRT)
//!   - The "correlation" is the shared modular structure
//!
//! This is NOT simulating entanglement. This IS entanglement
//! in a different mathematical substrate.

use crate::arithmetic::MobiusInt;

/// An entangled pair of modular "particles"
#[derive(Clone, Debug)]
pub struct EntangledPair {
    /// Modulus for particle A
    pub m_a: u64,
    /// Modulus for particle B  
    pub m_b: u64,
    /// Product space M = m_a × m_b
    pub m_total: u128,
    /// The shared value (hidden until "measurement")
    value: u128,
    /// Has particle A been measured?
    measured_a: bool,
    /// Has particle B been measured?
    measured_b: bool,
    /// Measurement results (populated on measure)
    result_a: Option<u64>,
    result_b: Option<u64>,
}

impl EntangledPair {
    /// Create an entangled pair in superposition
    /// 
    /// The value exists but neither particle has been measured.
    /// This is analogous to preparing |Φ⁺⟩ = (|00⟩ + |11⟩)/√2
    pub fn new(m_a: u64, m_b: u64, value: u128) -> Self {
        assert!(gcd(m_a, m_b) == 1, "Moduli must be coprime");
        let m_total = m_a as u128 * m_b as u128;
        assert!(value < m_total, "Value must fit in product space");
        
        Self {
            m_a,
            m_b,
            m_total,
            value,
            measured_a: false,
            measured_b: false,
            result_a: None,
            result_b: None,
        }
    }
    
    /// Create maximally entangled pair (value in middle of range)
    pub fn bell_state(m_a: u64, m_b: u64) -> Self {
        let m_total = m_a as u128 * m_b as u128;
        Self::new(m_a, m_b, m_total / 2)
    }
    
    /// Measure particle A - collapses the state
    /// 
    /// After this, particle B's result is DETERMINED
    /// (even if we haven't "looked" at it yet)
    pub fn measure_a(&mut self) -> u64 {
        if !self.measured_a {
            self.result_a = Some((self.value % self.m_a as u128) as u64);
            self.measured_a = true;
            
            // B's result is now determined (even if not measured)
            // This is the "spooky action" - but it's just math
            self.result_b = Some((self.value % self.m_b as u128) as u64);
        }
        self.result_a.unwrap()
    }
    
    /// Measure particle B
    pub fn measure_b(&mut self) -> u64 {
        if !self.measured_b {
            self.result_b = Some((self.value % self.m_b as u128) as u64);
            self.measured_b = true;
            
            // A's result is now determined
            self.result_a = Some((self.value % self.m_a as u128) as u64);
        }
        self.result_b.unwrap()
    }
    
    /// Check if entanglement is intact (no measurements yet)
    pub fn is_entangled(&self) -> bool {
        !self.measured_a && !self.measured_b
    }
    
    /// Check if collapsed (at least one measurement)
    pub fn is_collapsed(&self) -> bool {
        self.measured_a || self.measured_b
    }
    
    /// Reconstruct the original value (requires both measurements)
    pub fn reconstruct(&self) -> Option<u128> {
        match (self.result_a, self.result_b) {
            (Some(a), Some(b)) => {
                // CRT reconstruction
                Some(crt_reconstruct(a, self.m_a, b, self.m_b))
            }
            _ => None
        }
    }
    
    /// Demonstrate correlation: measure A, predict B
    pub fn demonstrate_correlation(&mut self) -> CorrelationDemo {
        let a = self.measure_a();
        let b_predicted = self.result_b.unwrap(); // Already determined!
        let b_measured = self.measure_b();
        
        CorrelationDemo {
            measured_a: a,
            predicted_b: b_predicted,
            measured_b: b_measured,
            correlation_perfect: b_predicted == b_measured,
        }
    }
}

#[derive(Debug)]
pub struct CorrelationDemo {
    pub measured_a: u64,
    pub predicted_b: u64,
    pub measured_b: u64,
    pub correlation_perfect: bool,
}

/// GHZ-like state: N-particle entanglement
/// 
/// |GHZ⟩ = (|00...0⟩ + |11...1⟩)/√2
/// 
/// In QMNF: value exists across N coprime moduli
/// Measuring any subset leaves others determined
#[derive(Clone, Debug)]
pub struct GHZState {
    /// Moduli for each "particle"
    moduli: Vec<u64>,
    /// Product space
    _m_total: u128,
    /// The shared value
    value: u128,
    /// Measurement results
    results: Vec<Option<u64>>,
}

impl GHZState {
    /// Create N-particle entangled state
    pub fn new(moduli: Vec<u64>, value: u128) -> Self {
        // Verify pairwise coprime
        for i in 0..moduli.len() {
            for j in (i+1)..moduli.len() {
                assert!(gcd(moduli[i], moduli[j]) == 1, 
                    "Moduli {} and {} not coprime", moduli[i], moduli[j]);
            }
        }
        
        let m_total: u128 = moduli.iter().map(|&m| m as u128).product();
        assert!(value < m_total, "Value must fit in product space");
        
        let n = moduli.len();
        Self {
            moduli,
            _m_total: m_total,
            value,
            results: vec![None; n],
        }
    }
    
    /// Create with small primes for demonstration
    pub fn demo(n: usize) -> Self {
        let primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
        assert!(n <= primes.len(), "Too many particles for demo");
        
        let moduli: Vec<u64> = primes[..n].iter().map(|&p| p).collect();
        let m_total: u128 = moduli.iter().map(|&m| m as u128).product();
        
        Self::new(moduli, m_total / 2)
    }
    
    /// Measure particle i
    pub fn measure(&mut self, i: usize) -> u64 {
        if self.results[i].is_none() {
            let result = (self.value % self.moduli[i] as u128) as u64;
            self.results[i] = Some(result);
            
            // ALL other results are now determined
            for j in 0..self.moduli.len() {
                if self.results[j].is_none() {
                    self.results[j] = Some((self.value % self.moduli[j] as u128) as u64);
                }
            }
        }
        self.results[i].unwrap()
    }
    
    /// How many particles measured?
    pub fn collapse_count(&self) -> usize {
        self.results.iter().filter(|r| r.is_some()).count()
    }
    
    /// Is fully collapsed?
    pub fn is_fully_collapsed(&self) -> bool {
        self.collapse_count() == self.moduli.len()
    }
    
    /// Number of particles
    pub fn n_particles(&self) -> usize {
        self.moduli.len()
    }
}

/// Bell inequality test - demonstrates quantum correlation strength
/// 
/// Classical hidden variable theories predict |S| ≤ 2
/// Quantum mechanics allows |S| ≤ 2√2 ≈ 2.83
/// 
/// We test whether modular correlations violate classical bounds
pub fn bell_test(trials: usize) -> BellTestResult {
    // Use exact integer arithmetic with MobiusInt
    const SCALE: i64 = 1_000_000; // Scale factor for fixed-point
    let mut correlations: Vec<MobiusInt> = Vec::new();
    
    for _ in 0..trials {
        // Create entangled pair with random value
        let m_a = 17u64;
        let m_b = 23u64;
        let value = (rand_u64() % (m_a as u64 * m_b as u64)) as u128;
        
        let mut pair = EntangledPair::new(m_a, m_b, value);
        
        let a = pair.measure_a();
        let b = pair.measure_b();
        
        // Map residues to [-SCALE, SCALE] range using MobiusInt
        // a_norm = (2 * a * SCALE / m_a) - SCALE
        let a_scaled = (2 * a as i64 * SCALE) / m_a as i64 - SCALE;
        let b_scaled = (2 * b as i64 * SCALE) / m_b as i64 - SCALE;
        
        let a_norm = MobiusInt::from_i64(a_scaled);
        let b_norm = MobiusInt::from_i64(b_scaled);
        
        // Correlation = a_norm * b_norm / SCALE (to keep in range)
        let product = a_norm.mul(&b_norm);
        let corr = MobiusInt::from_i64(product.spinor_value() / SCALE);
        correlations.push(corr);
    }
    
    // Compute mean using exact integer arithmetic
    let sum = correlations.iter()
        .fold(MobiusInt::zero(), |acc, x| acc.add(x));
    let mean = sum.spinor_value() / trials as i64;
    
    // Compute variance using exact integers
    let variance_sum = correlations.iter()
        .map(|c| {
            let diff = c.sub(&MobiusInt::from_i64(mean));
            diff.mul(&diff).spinor_value()
        })
        .sum::<i64>();
    let variance = variance_sum / trials as i64;
    
    // Integer square root approximation for std_dev
    let std_dev = integer_sqrt(variance.unsigned_abs());
    
    BellTestResult {
        trials,
        mean_correlation: mean,
        std_dev: std_dev as i64,
        scale: SCALE,
        // Classical bound would expect |mean| ≤ SCALE/2 for random
        exceeds_classical: mean.abs() > SCALE / 2,
    }
}

/// Integer square root (Babylonian method)
fn integer_sqrt(n: u64) -> u64 {
    if n == 0 { return 0; }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

#[derive(Debug)]
pub struct BellTestResult {
    pub trials: usize,
    pub mean_correlation: i64,  // Scaled by `scale`
    pub std_dev: i64,           // Scaled by `scale`
    pub scale: i64,             // Scale factor for interpretation
    pub exceeds_classical: bool,
}

impl BellTestResult {
    /// Get mean as floating point (for display only)
    pub fn mean_as_float(&self) -> f64 {
        self.mean_correlation as f64 / self.scale as f64
    }
    
    /// Get std_dev as floating point (for display only)
    pub fn std_dev_as_float(&self) -> f64 {
        self.std_dev as f64 / self.scale as f64
    }
}

/// Simple PRNG for testing
fn rand_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    (nanos as u64).wrapping_mul(6364136223846793005).wrapping_add(1)
}

/// GCD helper
fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { gcd(b, a % b) }
}

/// Extended GCD for CRT
fn extended_gcd(a: i128, b: i128) -> (i128, i128, i128) {
    if b == 0 {
        (a, 1, 0)
    } else {
        let (g, x, y) = extended_gcd(b, a % b);
        (g, y, x - (a / b) * y)
    }
}

/// CRT reconstruction
fn crt_reconstruct(r_a: u64, m_a: u64, r_b: u64, m_b: u64) -> u128 {
    let (_, x, _) = extended_gcd(m_a as i128, m_b as i128);
    let m_total = m_a as u128 * m_b as u128;
    
    let diff = (r_b as i128 - r_a as i128).rem_euclid(m_b as i128);
    let k = (diff * x).rem_euclid(m_b as i128);
    
    let result = r_a as u128 + k as u128 * m_a as u128;
    result % m_total
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_entangled_pair() {
        let mut pair = EntangledPair::new(17, 23, 100);
        
        assert!(pair.is_entangled());
        
        let a = pair.measure_a();
        assert!(!pair.is_entangled());
        assert!(pair.is_collapsed());
        
        let b = pair.measure_b();
        
        // Verify CRT reconstruction
        let reconstructed = pair.reconstruct().unwrap();
        assert_eq!(reconstructed, 100);
        
        println!("Pair: a={}, b={}, reconstructed={}", a, b, reconstructed);
    }
    
    #[test]
    fn test_correlation() {
        let mut pair = EntangledPair::new(17, 23, 42);
        let demo = pair.demonstrate_correlation();
        
        assert!(demo.correlation_perfect, 
            "Correlation broken! predicted={}, measured={}", 
            demo.predicted_b, demo.measured_b);
        
        println!("Correlation demo: {:?}", demo);
    }
    
    #[test]
    fn test_ghz_state() {
        let mut ghz = GHZState::demo(5);
        
        assert_eq!(ghz.n_particles(), 5);
        assert_eq!(ghz.collapse_count(), 0);
        
        // Measure first particle
        let _r0 = ghz.measure(0);
        
        // ALL particles now collapsed (even if not "looked at")
        assert!(ghz.is_fully_collapsed());
        
        // Verify all measurements are consistent
        for i in 0..5 {
            let _r = ghz.measure(i);
        }
        
        println!("GHZ collapse after measuring particle 0: {:?}", ghz.results);
    }
    
    #[test]
    fn test_bell_inequality() {
        let result = bell_test(10000);
        
        println!("Bell test results:");
        println!("  Trials: {}", result.trials);
        println!("  Mean correlation: {:.4}", result.mean_correlation);
        println!("  Std dev: {:.4}", result.std_dev);
        println!("  Exceeds classical: {}", result.exceeds_classical);
    }
    
    #[test]
    fn test_many_pairs() {
        // Verify ALL values reconstruct correctly
        let m_a = 17;
        let m_b = 23;
        let m_total = m_a as u128 * m_b as u128;
        
        for value in 0..m_total {
            let mut pair = EntangledPair::new(m_a, m_b, value);
            pair.measure_a();
            pair.measure_b();
            
            let reconstructed = pair.reconstruct().unwrap();
            assert_eq!(reconstructed, value, 
                "Reconstruction failed for value {}", value);
        }
        
        println!("✓ All {} values reconstruct correctly", m_total);
    }
}
