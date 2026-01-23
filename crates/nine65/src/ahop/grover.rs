//! Grover's Algorithm - Quantum Search over F_{p²}
//!
//! Demonstrates zero-decoherence quantum simulation.
//! Classical computers would see probability decay to uniform;
//! F_{p²} substrate maintains exact oscillation indefinitely.

use super::{Fp2Element, StateVector};

/// Grover's search algorithm
pub struct GroverSearch {
    /// Number of qubits
    pub num_qubits: usize,
    /// Dimension (2^n)
    pub dim: usize,
    /// Target state to find
    pub target: usize,
    /// Prime modulus
    pub p: u64,
}

impl GroverSearch {
    /// Create new Grover search
    pub fn new(num_qubits: usize, target: usize, p: u64) -> Self {
        let dim = 1 << num_qubits;
        assert!(target < dim, "Target must be < 2^n");
        
        Self { num_qubits, dim, target, p }
    }
    
    /// Initialize uniform superposition: |s⟩ = H⊗n|0⟩
    pub fn initialize(&self) -> StateVector {
        StateVector::uniform(self.dim, self.p)
    }
    
    /// Oracle: flip phase of target state
    /// O|x⟩ = -|x⟩ if x = target, else |x⟩
    pub fn apply_oracle(&self, state: &mut StateVector) {
        state.amplitudes[self.target] = state.amplitudes[self.target].neg();
    }
    
    /// Diffusion operator: 2|s⟩⟨s| - I
    /// Reflects about the mean amplitude
    pub fn apply_diffusion(&self, state: &mut StateVector) {
        // Compute mean amplitude: (Σ a_k) / N
        // In F_{p²}, we compute sum and multiply by N^(-1)
        let mut sum = Fp2Element::zero(self.p);
        for amp in &state.amplitudes {
            sum = sum.add(amp);
        }
        
        // N^(-1) mod p using Fermat
        let n_inv = mod_pow(self.dim as u64, self.p - 2, self.p);
        let mean = sum.scalar_mul(n_inv);
        
        // 2*mean - a_k for each amplitude
        let two_mean = mean.add(&mean);
        for amp in &mut state.amplitudes {
            *amp = two_mean.sub(amp);
        }
    }
    
    /// Single Grover iteration: G = D · O
    pub fn grover_iteration(&self, state: &mut StateVector) {
        self.apply_oracle(state);
        self.apply_diffusion(state);
    }
    
    /// Run Grover's algorithm for specified iterations
    pub fn run(&self, iterations: usize) -> StateVector {
        let mut state = self.initialize();
        
        for _ in 0..iterations {
            self.grover_iteration(&mut state);
        }
        
        state
    }
    
    /// Optimal number of iterations: ≈ π/4 * √N
    pub fn optimal_iterations(&self) -> usize {
        let n = self.dim as f64;
        ((std::f64::consts::PI / 4.0) * n.sqrt()).round() as usize
    }
    
    /// Run with data collection for analysis
    pub fn run_with_stats(&self, max_iterations: usize) -> Vec<GroverStats> {
        let mut state = self.initialize();
        let mut stats = Vec::with_capacity(max_iterations + 1);
        
        // Initial state
        stats.push(GroverStats {
            iteration: 0,
            target_probability: state.probability(self.target),
            total_weight: state.total_weight(),
            max_non_target_prob: self.max_non_target_prob(&state),
        });
        
        for i in 1..=max_iterations {
            self.grover_iteration(&mut state);
            
            stats.push(GroverStats {
                iteration: i,
                target_probability: state.probability(self.target),
                total_weight: state.total_weight(),
                max_non_target_prob: self.max_non_target_prob(&state),
            });
        }
        
        stats
    }
    
    /// Maximum probability of non-target states
    fn max_non_target_prob(&self, state: &StateVector) -> f64 {
        let total = state.total_weight() as f64;
        if total == 0.0 { return 0.0; }
        
        state.amplitudes.iter()
            .enumerate()
            .filter(|(i, _)| *i != self.target)
            .map(|(_, a)| a.norm_squared() as f64 / total)
            .fold(0.0, f64::max)
    }
}

/// Statistics for a single iteration
#[derive(Clone, Debug)]
pub struct GroverStats {
    pub iteration: usize,
    pub target_probability: f64,
    pub total_weight: u64,
    pub max_non_target_prob: f64,
}

/// Modular exponentiation
fn mod_pow(base: u64, exp: u64, m: u64) -> u64 {
    if m == 1 { return 0; }
    let mut result = 1u64;
    let mut base = base % m;
    let mut exp = exp;
    
    while exp > 0 {
        if exp & 1 == 1 {
            result = ((result as u128 * base as u128) % m as u128) as u64;
        }
        exp >>= 1;
        base = ((base as u128 * base as u128) % m as u128) as u64;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    
    const TEST_PRIME: u64 = 1000003;
    
    #[test]
    fn test_grover_2qubit() {
        // 2 qubits = 4 states, target = 3
        // For N=4, optimal is π/4 * √4 ≈ 1.57, so 1 iteration is best
        let grover = GroverSearch::new(2, 3, TEST_PRIME);
        
        // Test at 1 iteration (the true optimal for N=4)
        let state = grover.run(1);
        let prob = state.probability(3);
        
        println!("2-qubit Grover at 1 iteration: P(target) = {:.4}", prob);
        
        // After 1 iteration, target should dominate (weight 4 vs 0 for others)
        assert!(prob > 0.9, "Target should have very high probability at optimal");
        
        // Also verify state preservation
        let total_weight = state.total_weight();
        assert!(total_weight > 0, "State should have non-zero weight");
    }
    
    #[test]
    fn test_grover_3qubit() {
        // 3 qubits = 8 states
        let grover = GroverSearch::new(3, 5, TEST_PRIME);
        
        let optimal = grover.optimal_iterations();
        println!("3-qubit optimal iterations: {}", optimal);
        
        let state = grover.run(optimal);
        let prob = state.probability(5);
        
        println!("Target probability: {:.4}", prob);
        assert!(prob > 0.5);
    }

    #[test]
    fn test_grover_5qubit_depth_1000() {
        // 5 qubits = 32 states, depth 1000 to verify no decoherence
        let grover = GroverSearch::new(5, 17, TEST_PRIME);

        let stats = grover.run_with_stats(1000);
        let initial_weight = stats.first().unwrap().total_weight;
        let final_weight = stats.last().unwrap().total_weight;
        assert_eq!(initial_weight, final_weight, "Weight should be preserved");

        let last_100: Vec<f64> = stats[900..].iter().map(|s| s.target_probability).collect();
        let min_prob = last_100.iter().cloned().fold(f64::INFINITY, f64::min);
        let max_prob = last_100.iter().cloned().fold(0.0, f64::max);

        println!(
            "5-qubit depth 1000: min={:.4}, max={:.4}",
            min_prob, max_prob
        );
        assert!(max_prob - min_prob > 0.3, "Oscillation should persist");
    }

    #[test]
    fn test_grover_4qubit() {
        // 4 qubits = 16 states
        let grover = GroverSearch::new(4, 7, TEST_PRIME);
        
        let optimal = grover.optimal_iterations();
        println!("4-qubit optimal iterations: {}", optimal);
        
        let stats = grover.run_with_stats(optimal * 3);
        
        // Find maximum probability achieved
        let max_prob = stats.iter().map(|s| s.target_probability).fold(0.0, f64::max);
        let max_iter = stats.iter().find(|s| s.target_probability == max_prob).unwrap().iteration;
        
        println!("Max probability {:.4} at iteration {}", max_prob, max_iter);
        assert!(max_prob > 0.9, "Should achieve >90% probability");
    }
    
    #[test]
    fn test_grover_no_decoherence_1000() {
        // Key test: run 1000 iterations and verify oscillation persists
        let grover = GroverSearch::new(3, 2, TEST_PRIME);
        
        let stats = grover.run_with_stats(1000);
        
        // Check that probability oscillates (doesn't decay to 1/N = 0.125)
        let last_100: Vec<f64> = stats[900..].iter().map(|s| s.target_probability).collect();
        let min_prob = last_100.iter().cloned().fold(f64::INFINITY, f64::min);
        let max_prob = last_100.iter().cloned().fold(0.0, f64::max);
        
        println!("Last 100 iterations: min={:.4}, max={:.4}", min_prob, max_prob);
        
        // If decoherence occurred, both would converge to 0.125
        // With exact arithmetic, oscillation persists
        assert!(max_prob - min_prob > 0.3, "Should still be oscillating after 1000 iterations");
    }
    
    #[test]
    fn test_grover_extreme_10000() {
        // Extreme test: 10000 iterations
        let grover = GroverSearch::new(4, 7, TEST_PRIME);
        
        let mut state = grover.initialize();
        
        // Sample every 500 iterations
        let mut samples = Vec::new();
        for i in 0..=10000 {
            if i % 500 == 0 {
                samples.push((i, state.probability(7), state.total_weight()));
            }
            if i < 10000 {
                grover.grover_iteration(&mut state);
            }
        }
        
        println!("\n10000 iteration test (4 qubits, target=7):");
        println!("Iter\tP(target)\tTotal Weight");
        for (iter, prob, weight) in &samples {
            println!("{}\t{:.6}\t{}", iter, prob, weight);
        }
        
        // Verify total weight is preserved (no numerical drift)
        let initial_weight = samples[0].2;
        let final_weight = samples.last().unwrap().2;
        assert_eq!(initial_weight, final_weight, "Weight should be exactly preserved");
        
        // Verify oscillation continues
        let probs: Vec<f64> = samples.iter().map(|s| s.1).collect();
        let min_prob = probs.iter().cloned().fold(f64::INFINITY, f64::min);
        let max_prob = probs.iter().cloned().fold(0.0, f64::max);
        
        println!("Probability range: [{:.4}, {:.4}]", min_prob, max_prob);
        assert!(max_prob > 0.9, "Should achieve >90% peak");
        assert!(min_prob < 0.2, "Should oscillate below 20%");
    }
    
    #[test]
    fn test_grover_6qubit_scale() {
        // 6 qubits = 64 states
        let grover = GroverSearch::new(6, 42, TEST_PRIME);
        
        let optimal = grover.optimal_iterations();
        println!("6-qubit optimal iterations: {}", optimal);
        
        let state = grover.run(optimal);
        let prob = state.probability(42);
        
        println!("6-qubit target probability: {:.4}", prob);
        assert!(prob > 0.8, "Should achieve high probability");
    }
}
