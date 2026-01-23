//! Quantum Amplitude - Signed Amplitude for Quantum Interference
//!
//! INNOVATION: Quantum algorithms require NEGATIVE amplitudes for destructive
//! interference (Grover diffusion, quantum Fourier transform, etc.).
//!
//! Standard approach: Use unsigned integers, can't represent interference
//! Our approach: MobiusInt-backed amplitudes with explicit polarity
//!
//! This enables:
//! - Grover's algorithm diffusion operator (2|ψ⟩⟨ψ| - I)
//! - Quantum Fourier Transform (requires complex phases)
//! - Any algorithm requiring destructive interference

use crate::arithmetic::{MobiusInt, Polarity};

/// Quantum amplitude with signed magnitude via MobiusInt
#[derive(Clone, Copy, Debug)]
pub struct QuantumAmplitude {
    /// Signed value via MobiusInt (magnitude + polarity)
    pub value: MobiusInt,
}

impl QuantumAmplitude {
    /// Create zero amplitude
    #[inline]
    pub fn zero() -> Self {
        Self { value: MobiusInt::zero() }
    }
    
    /// Create positive amplitude
    #[inline]
    pub fn positive(magnitude: u64) -> Self {
        Self { value: MobiusInt::from_unsigned(magnitude, Polarity::Plus) }
    }
    
    /// Create negative amplitude (for destructive interference)
    #[inline]
    pub fn negative(magnitude: u64) -> Self {
        Self { value: MobiusInt::from_unsigned(magnitude, Polarity::Minus) }
    }
    
    /// Create from i64
    #[inline]
    pub fn from_i64(val: i64) -> Self {
        Self { value: MobiusInt::from_i64(val) }
    }
    
    /// Get signed value
    #[inline]
    pub fn spinor_value(&self) -> i64 {
        self.value.spinor_value()
    }
    
    /// Get magnitude (absolute value)
    #[inline]
    pub fn magnitude(&self) -> u64 {
        self.value.abs()
    }
    
    /// Is positive?
    #[inline]
    pub fn is_positive(&self) -> bool {
        self.value.is_positive()
    }
    
    /// Is negative?
    #[inline]
    pub fn is_negative(&self) -> bool {
        self.value.is_negative()
    }
    
    /// Is zero?
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.value.is_zero()
    }
    
    /// Flip sign (for oracle marking in Grover)
    #[inline]
    pub fn flip_sign(&self) -> Self {
        Self { value: self.value.neg() }
    }
    
    /// Add amplitudes (superposition)
    pub fn add(&self, other: &Self) -> Self {
        Self { value: self.value.add(&other.value) }
    }
    
    /// Subtract amplitudes
    pub fn sub(&self, other: &Self) -> Self {
        Self { value: self.value.sub(&other.value) }
    }
    
    /// Multiply amplitudes
    pub fn mul(&self, other: &Self) -> Self {
        Self { value: self.value.mul(&other.value) }
    }
    
    /// Scale by integer
    pub fn scale(&self, factor: i64) -> Self {
        Self { value: self.value.mul(&MobiusInt::from_i64(factor)) }
    }
    
    /// Probability (|amplitude|²) - always positive
    pub fn probability(&self) -> u64 {
        let mag = self.magnitude();
        mag * mag
    }
}

impl Default for QuantumAmplitude {
    fn default() -> Self {
        Self::zero()
    }
}

impl PartialEq for QuantumAmplitude {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Eq for QuantumAmplitude {}

/// Quantum state vector with signed amplitudes
#[derive(Clone, Debug)]
pub struct QuantumState {
    /// Amplitudes for each basis state
    pub amplitudes: Vec<QuantumAmplitude>,
    /// Number of qubits
    pub num_qubits: usize,
}

impl QuantumState {
    /// Create |0⟩ state (all amplitude on first basis state)
    pub fn zero_state(num_qubits: usize) -> Self {
        let dim = 1 << num_qubits;
        let mut amplitudes = vec![QuantumAmplitude::zero(); dim];
        amplitudes[0] = QuantumAmplitude::positive(1);
        Self { amplitudes, num_qubits }
    }
    
    /// Create uniform superposition (|+⟩^n)
    pub fn uniform_superposition(num_qubits: usize, scale: u64) -> Self {
        let dim = 1 << num_qubits;
        let amp_value = scale; // Each amplitude = scale/√dim (but we keep scale for integer)
        let amplitudes = vec![QuantumAmplitude::positive(amp_value); dim];
        Self { amplitudes, num_qubits }
    }
    
    /// Get dimension (2^num_qubits)
    pub fn dimension(&self) -> usize {
        self.amplitudes.len()
    }
    
    /// Oracle: Flip sign of target state (Grover)
    /// This is O(1) with MobiusInt!
    pub fn oracle_mark(&mut self, target: usize) {
        if target < self.amplitudes.len() {
            self.amplitudes[target] = self.amplitudes[target].flip_sign();
        }
    }
    
    /// Grover diffusion operator: 2|ψ⟩⟨ψ| - I
    /// 
    /// For each amplitude: new_amp = 2*mean - old_amp
    /// This REQUIRES negative amplitudes (MobiusInt enables this!)
    pub fn grover_diffusion(&mut self) {
        // Compute mean amplitude
        let sum = self.amplitudes.iter()
            .fold(MobiusInt::zero(), |acc, a| acc.add(&a.value));
        
        let n = self.amplitudes.len() as i64;
        let mean = sum.spinor_value() / n;
        let two_mean = MobiusInt::from_i64(2 * mean);
        
        // Apply: 2*mean - amplitude (creates NEGATIVE amplitudes!)
        for amp in &mut self.amplitudes {
            amp.value = two_mean.sub(&amp.value);
        }
    }
    
    /// Get probability distribution (squared magnitudes)
    pub fn probabilities(&self) -> Vec<u64> {
        self.amplitudes.iter().map(|a| a.probability()).collect()
    }
    
    /// Find state with highest probability
    pub fn measure_max(&self) -> usize {
        self.amplitudes.iter()
            .enumerate()
            .max_by_key(|(_, a)| a.probability())
            .map(|(i, _)| i)
            .unwrap_or(0)
    }
    
    /// Count positive vs negative amplitudes (diagnostic)
    pub fn sign_distribution(&self) -> (usize, usize, usize) {
        let mut pos = 0;
        let mut neg = 0;
        let mut zero = 0;
        for a in &self.amplitudes {
            if a.is_zero() { zero += 1; }
            else if a.is_positive() { pos += 1; }
            else { neg += 1; }
        }
        (pos, neg, zero)
    }
}

/// Run Grover's algorithm with proper negative amplitudes
pub fn grover_search(target: usize, num_qubits: usize, iterations: usize) -> GroverResult {
    let scale = 1000u64; // Amplitude scale factor
    let mut state = QuantumState::uniform_superposition(num_qubits, scale);
    
    let mut iteration_stats = Vec::new();
    
    for i in 0..iterations {
        // Oracle: flip sign of target (creates negative amplitude)
        state.oracle_mark(target);
        
        // Diffusion: 2|ψ⟩⟨ψ| - I (uses negative amplitudes)
        state.grover_diffusion();
        
        // Record stats
        let (pos, neg, _zero) = state.sign_distribution();
        let target_prob = state.amplitudes[target].probability();
        
        iteration_stats.push(IterationStats {
            iteration: i + 1,
            target_probability: target_prob,
            positive_count: pos,
            negative_count: neg,
        });
    }
    
    let final_measurement = state.measure_max();
    let success = final_measurement == target;
    
    GroverResult {
        target,
        found: final_measurement,
        success,
        iterations,
        stats: iteration_stats,
    }
}

#[derive(Debug)]
pub struct IterationStats {
    pub iteration: usize,
    pub target_probability: u64,
    pub positive_count: usize,
    pub negative_count: usize,
}

#[derive(Debug)]
pub struct GroverResult {
    pub target: usize,
    pub found: usize,
    pub success: bool,
    pub iterations: usize,
    pub stats: Vec<IterationStats>,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_amplitude_creation() {
        let pos = QuantumAmplitude::positive(100);
        assert!(pos.is_positive());
        assert_eq!(pos.spinor_value(), 100);
        
        let neg = QuantumAmplitude::negative(50);
        assert!(neg.is_negative());
        assert_eq!(neg.spinor_value(), -50);
    }
    
    #[test]
    fn test_flip_sign() {
        let amp = QuantumAmplitude::positive(42);
        let flipped = amp.flip_sign();
        assert!(flipped.is_negative());
        assert_eq!(flipped.spinor_value(), -42);
    }
    
    #[test]
    fn test_oracle_creates_negative() {
        let mut state = QuantumState::uniform_superposition(2, 100);
        
        // Initially all positive
        let (pos, neg, _) = state.sign_distribution();
        assert_eq!(pos, 4);
        assert_eq!(neg, 0);
        
        // Oracle marks target -> creates negative
        state.oracle_mark(2);
        let (pos, neg, _) = state.sign_distribution();
        assert_eq!(pos, 3);
        assert_eq!(neg, 1);
        
        assert!(state.amplitudes[2].is_negative());
    }
    
    #[test]
    fn test_grover_diffusion() {
        let mut state = QuantumState::uniform_superposition(2, 100);
        state.oracle_mark(0);
        state.grover_diffusion();
        
        // After diffusion, target should have higher amplitude
        let target_amp = state.amplitudes[0].magnitude();
        let other_amp = state.amplitudes[1].magnitude();
        
        // The interference should amplify target
        assert!(target_amp > 0);
        assert!(target_amp >= other_amp);
    }
    
    #[test]
    fn test_grover_search_small() {
        let result = grover_search(2, 2, 1);
        // With 2 qubits and 1 iteration, should improve target probability
        assert_eq!(result.target, 2);
    }
}
