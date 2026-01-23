//! AHOP - Axiomatic Holographic Operator-state Projection
//!
//! Implements finite-field quantum simulation over F_{p²}.
//! This provides ZERO DECOHERENCE because all arithmetic is exact.
//!
//! Key insight: Complex amplitudes α = a + bi are represented as
//! elements of F_{p²} = F_p[i]/(i² + 1), enabling exact computation.

pub mod grover;
pub use grover::{GroverSearch, GroverStats};

/// Element of F_{p²} = F_p[i]/(i² + 1)
/// Represents a + bi where a, b ∈ F_p
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fp2Element {
    /// Real part
    pub a: u64,
    /// Imaginary part
    pub b: u64,
    /// The prime modulus
    pub p: u64,
}

impl Fp2Element {
    /// Create new element
    pub fn new(a: u64, b: u64, p: u64) -> Self {
        Self {
            a: a % p,
            b: b % p,
            p,
        }
    }
    
    /// Zero element
    pub fn zero(p: u64) -> Self {
        Self { a: 0, b: 0, p }
    }
    
    /// One element
    pub fn one(p: u64) -> Self {
        Self { a: 1, b: 0, p }
    }
    
    /// Imaginary unit i
    pub fn i(p: u64) -> Self {
        Self { a: 0, b: 1, p }
    }
    
    /// Addition in F_{p²}
    pub fn add(&self, other: &Self) -> Self {
        assert_eq!(self.p, other.p);
        Self {
            a: (self.a + other.a) % self.p,
            b: (self.b + other.b) % self.p,
            p: self.p,
        }
    }
    
    /// Subtraction in F_{p²}
    pub fn sub(&self, other: &Self) -> Self {
        assert_eq!(self.p, other.p);
        Self {
            a: if self.a >= other.a { self.a - other.a } else { self.p - other.a + self.a },
            b: if self.b >= other.b { self.b - other.b } else { self.p - other.b + self.b },
            p: self.p,
        }
    }
    
    /// Negation
    pub fn neg(&self) -> Self {
        Self {
            a: if self.a == 0 { 0 } else { self.p - self.a },
            b: if self.b == 0 { 0 } else { self.p - self.b },
            p: self.p,
        }
    }
    
    /// Multiplication in F_{p²}
    /// (a + bi)(c + di) = (ac - bd) + (ad + bc)i
    pub fn mul(&self, other: &Self) -> Self {
        assert_eq!(self.p, other.p);
        
        let ac = (self.a as u128 * other.a as u128) % self.p as u128;
        let bd = (self.b as u128 * other.b as u128) % self.p as u128;
        let ad = (self.a as u128 * other.b as u128) % self.p as u128;
        let bc = (self.b as u128 * other.a as u128) % self.p as u128;
        
        // Real: ac - bd (mod p)
        let real = if ac >= bd {
            (ac - bd) as u64
        } else {
            (self.p as u128 - bd + ac) as u64
        };
        
        // Imag: ad + bc (mod p)
        let imag = ((ad + bc) % self.p as u128) as u64;
        
        Self { a: real, b: imag, p: self.p }
    }
    
    /// Complex conjugate: (a + bi)* = a - bi
    pub fn conj(&self) -> Self {
        Self {
            a: self.a,
            b: if self.b == 0 { 0 } else { self.p - self.b },
            p: self.p,
        }
    }
    
    /// Norm squared: |a + bi|² = a² + b²
    pub fn norm_squared(&self) -> u64 {
        let a2 = (self.a as u128 * self.a as u128) % self.p as u128;
        let b2 = (self.b as u128 * self.b as u128) % self.p as u128;
        ((a2 + b2) % self.p as u128) as u64
    }
    
    /// Multiplicative inverse using Fermat's little theorem
    /// (a + bi)^(-1) = (a - bi) / (a² + b²)
    pub fn inv(&self) -> Option<Self> {
        let norm_sq = self.norm_squared();
        if norm_sq == 0 {
            return None;
        }
        
        // Compute norm_sq^(-1) mod p using Fermat
        let norm_inv = mod_pow(norm_sq, self.p - 2, self.p);
        
        // Multiply conjugate by inverse of norm squared
        let conj = self.conj();
        Some(Self {
            a: ((conj.a as u128 * norm_inv as u128) % self.p as u128) as u64,
            b: ((conj.b as u128 * norm_inv as u128) % self.p as u128) as u64,
            p: self.p,
        })
    }
    
    /// Scalar multiplication
    pub fn scalar_mul(&self, k: u64) -> Self {
        Self {
            a: ((self.a as u128 * k as u128) % self.p as u128) as u64,
            b: ((self.b as u128 * k as u128) % self.p as u128) as u64,
            p: self.p,
        }
    }
}

/// State vector in F_{p²}^d
#[derive(Clone, Debug)]
pub struct StateVector {
    /// Amplitudes (unnormalized)
    pub amplitudes: Vec<Fp2Element>,
    /// Dimension (2^n for n qubits)
    pub dim: usize,
    /// Prime modulus
    pub p: u64,
}

impl StateVector {
    /// Create new state vector for n qubits, initialized to |0⟩
    pub fn new(num_qubits: usize, p: u64) -> Self {
        let dim = 1 << num_qubits;
        let mut amplitudes = vec![Fp2Element::zero(p); dim];
        amplitudes[0] = Fp2Element::one(p); // Start in |0...0⟩
        Self { amplitudes, dim, p }
    }
    
    /// Create zero state
    pub fn zero(dim: usize, p: u64) -> Self {
        Self {
            amplitudes: vec![Fp2Element::zero(p); dim],
            dim,
            p,
        }
    }
    
    /// Create computational basis state |k⟩
    pub fn basis(k: usize, dim: usize, p: u64) -> Self {
        let mut amplitudes = vec![Fp2Element::zero(p); dim];
        amplitudes[k] = Fp2Element::one(p);
        Self { amplitudes, dim, p }
    }
    
    /// Create uniform superposition (unnormalized)
    pub fn uniform(dim: usize, p: u64) -> Self {
        Self {
            amplitudes: vec![Fp2Element::one(p); dim],
            dim,
            p,
        }
    }
    
    /// Get number of qubits
    pub fn num_qubits(&self) -> usize {
        (self.dim as f64).log2() as usize
    }
    
    /// Get prime modulus
    pub fn prime(&self) -> u64 {
        self.p
    }
    
    /// Get dimension
    pub fn dimension(&self) -> usize {
        self.dim
    }
    
    /// Negate amplitude at index (for oracle phase flip)
    pub fn negate_amplitude(&mut self, index: usize) {
        if index < self.dim {
            self.amplitudes[index] = self.amplitudes[index].neg();
        }
    }
    
    /// Apply Hadamard gate to single qubit
    pub fn hadamard_qubit(&mut self, qubit: usize, scale: &Fp2Element) {
        let mask = 1 << qubit;
        
        for i in 0..self.dim {
            if i & mask == 0 {
                let j = i | mask;
                
                let a_i = self.amplitudes[i];
                let a_j = self.amplitudes[j];
                
                // Hadamard: |0⟩ → (|0⟩ + |1⟩)/√2, |1⟩ → (|0⟩ - |1⟩)/√2
                // In F_{p²}: new_i = scale * (a_i + a_j), new_j = scale * (a_i - a_j)
                self.amplitudes[i] = scale.mul(&a_i.add(&a_j));
                self.amplitudes[j] = scale.mul(&a_i.sub(&a_j));
            }
        }
    }
    
    /// Add two state vectors
    pub fn add(&self, other: &Self) -> Self {
        assert_eq!(self.dim, other.dim);
        Self {
            amplitudes: self.amplitudes.iter()
                .zip(other.amplitudes.iter())
                .map(|(a, b)| a.add(b))
                .collect(),
            dim: self.dim,
            p: self.p,
        }
    }
    
    /// Subtract two state vectors
    pub fn sub(&self, other: &Self) -> Self {
        assert_eq!(self.dim, other.dim);
        Self {
            amplitudes: self.amplitudes.iter()
                .zip(other.amplitudes.iter())
                .map(|(a, b)| a.sub(b))
                .collect(),
            dim: self.dim,
            p: self.p,
        }
    }
    
    /// Inner product ⟨self|other⟩ = Σ self_k* × other_k
    pub fn inner_product(&self, other: &Self) -> Fp2Element {
        assert_eq!(self.dim, other.dim);
        
        let mut result = Fp2Element::zero(self.p);
        for (a, b) in self.amplitudes.iter().zip(other.amplitudes.iter()) {
            let term = a.conj().mul(b);
            result = result.add(&term);
        }
        result
    }
    
    /// Total weight: Σ |a_k|²
    pub fn total_weight(&self) -> u64 {
        self.amplitudes.iter()
            .map(|a| a.norm_squared())
            .fold(0u64, |acc, x| (acc + x) % self.p)
    }
    
    /// Get probability of state k (as fraction of total weight)
    pub fn probability(&self, k: usize) -> f64 {
        let weight_k = self.amplitudes[k].norm_squared() as f64;
        let total = self.total_weight() as f64;
        if total == 0.0 { 0.0 } else { weight_k / total }
    }
    
    /// Apply single-qubit gate to qubit q
    pub fn apply_single_gate(&mut self, gate: &[[Fp2Element; 2]; 2], qubit: usize, _num_qubits: usize) {
        let mask = 1 << qubit;
        
        for i in 0..self.dim {
            if i & mask == 0 {
                let j = i | mask;
                
                // |i⟩ and |j⟩ form a pair
                let a_i = self.amplitudes[i];
                let a_j = self.amplitudes[j];
                
                // Apply 2x2 gate
                // new_i = gate[0][0] * a_i + gate[0][1] * a_j
                // new_j = gate[1][0] * a_i + gate[1][1] * a_j
                self.amplitudes[i] = gate[0][0].mul(&a_i).add(&gate[0][1].mul(&a_j));
                self.amplitudes[j] = gate[1][0].mul(&a_i).add(&gate[1][1].mul(&a_j));
            }
        }
    }
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
    
    const TEST_PRIME: u64 = 1000003;  // Prime for testing
    
    #[test]
    fn test_fp2_add() {
        let a = Fp2Element::new(3, 4, TEST_PRIME);
        let b = Fp2Element::new(1, 2, TEST_PRIME);
        let c = a.add(&b);
        
        assert_eq!(c.a, 4);
        assert_eq!(c.b, 6);
    }
    
    #[test]
    fn test_fp2_mul() {
        // (3 + 4i)(1 + 2i) = 3 + 6i + 4i + 8i² = 3 + 10i - 8 = -5 + 10i
        let a = Fp2Element::new(3, 4, TEST_PRIME);
        let b = Fp2Element::new(1, 2, TEST_PRIME);
        let c = a.mul(&b);
        
        assert_eq!(c.a, TEST_PRIME - 5);  // -5 mod p
        assert_eq!(c.b, 10);
    }
    
    #[test]
    fn test_fp2_conj() {
        let a = Fp2Element::new(3, 4, TEST_PRIME);
        let conj = a.conj();
        
        assert_eq!(conj.a, 3);
        assert_eq!(conj.b, TEST_PRIME - 4);  // -4 mod p
    }
    
    #[test]
    fn test_fp2_norm_squared() {
        // |3 + 4i|² = 9 + 16 = 25
        let a = Fp2Element::new(3, 4, TEST_PRIME);
        assert_eq!(a.norm_squared(), 25);
    }
    
    #[test]
    fn test_fp2_inverse() {
        let a = Fp2Element::new(3, 4, TEST_PRIME);
        let a_inv = a.inv().unwrap();
        let product = a.mul(&a_inv);
        
        assert_eq!(product.a, 1);
        assert_eq!(product.b, 0);
    }
    
    #[test]
    fn test_state_uniform() {
        let state = StateVector::uniform(4, TEST_PRIME);
        
        assert_eq!(state.dim, 4);
        assert_eq!(state.total_weight(), 4);  // 4 states, each with weight 1
    }
    
    #[test]
    fn test_state_inner_product() {
        let s1 = StateVector::basis(0, 4, TEST_PRIME);
        let s2 = StateVector::basis(0, 4, TEST_PRIME);
        let s3 = StateVector::basis(1, 4, TEST_PRIME);
        
        // ⟨0|0⟩ = 1
        let ip12 = s1.inner_product(&s2);
        assert_eq!(ip12.a, 1);
        assert_eq!(ip12.b, 0);
        
        // ⟨0|1⟩ = 0
        let ip13 = s1.inner_product(&s3);
        assert_eq!(ip13.a, 0);
        assert_eq!(ip13.b, 0);
    }
    
    #[test]
    fn test_probability() {
        let state = StateVector::uniform(4, TEST_PRIME);
        
        // Each state should have probability 1/4
        for k in 0..4 {
            let prob = state.probability(k);
            assert!((prob - 0.25).abs() < 0.001);
        }
    }
}
