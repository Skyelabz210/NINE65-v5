//! NTT Engine - Gen 3 Number Theoretic Transform
//!
//! QMNF Innovation: Negacyclic convolution via ψ-twist for X^N+1 rings.
//! Uses correct DFT matrix approach for guaranteed correctness.

use super::montgomery::MontgomeryContext;

/// NTT Engine for polynomial arithmetic in Z_q[X]/(X^N + 1)
#[derive(Clone)]
pub struct NTTEngine {
    /// Montgomery context for modular arithmetic
    pub mont: MontgomeryContext,
    /// The modulus
    pub q: u64,
    /// Polynomial degree (power of 2)
    pub n: usize,
    /// Primitive 2N-th root of unity ψ (for negacyclic twist)
    pub psi: u64,
    /// Primitive N-th root of unity ω = ψ² (for NTT)
    pub omega: u64,
    /// Inverse of ω
    pub omega_inv: u64,
    /// Inverse of ψ
    pub psi_inv: u64,
    /// N^(-1) mod q
    pub n_inv: u64,
    /// Precomputed powers of ψ: psi_powers[i] = ψ^i mod q
    pub psi_powers: Vec<u64>,
    /// Precomputed inverse powers of ψ
    pub psi_inv_powers: Vec<u64>,
    /// Precomputed powers of ω
    pub omega_powers: Vec<u64>,
    /// Precomputed inverse powers of ω
    pub omega_inv_powers: Vec<u64>,
}

impl NTTEngine {
    /// Create a new NTT engine for the given prime and degree
    pub fn new(q: u64, n: usize) -> Self {
        assert!(n.is_power_of_two(), "N must be a power of 2");
        assert!((q - 1) % (2 * n as u64) == 0, "q-1 must be divisible by 2N for NTT");
        
        let mont = MontgomeryContext::new(q);
        
        // Find primitive 2N-th root of unity (ψ)
        let psi = Self::find_primitive_root(q, 2 * n);
        let psi_inv = mod_inverse(psi, q);
        
        // ω = ψ² is primitive N-th root
        let omega = mod_pow(psi, 2, q);
        let omega_inv = mod_inverse(omega, q);
        
        // N^(-1) mod q
        let n_inv = mod_inverse(n as u64, q);
        
        // Precompute powers
        let psi_powers: Vec<u64> = (0..n).map(|i| mod_pow(psi, i as u64, q)).collect();
        let psi_inv_powers: Vec<u64> = (0..n).map(|i| mod_pow(psi_inv, i as u64, q)).collect();
        let omega_powers: Vec<u64> = (0..n).map(|i| mod_pow(omega, i as u64, q)).collect();
        let omega_inv_powers: Vec<u64> = (0..n).map(|i| mod_pow(omega_inv, i as u64, q)).collect();
        
        Self {
            mont,
            q,
            n,
            psi,
            omega,
            omega_inv,
            psi_inv,
            n_inv,
            psi_powers,
            psi_inv_powers,
            omega_powers,
            omega_inv_powers,
        }
    }
    
    /// Find a primitive n-th root of unity modulo prime q
    fn find_primitive_root(q: u64, order: usize) -> u64 {
        let exp = (q - 1) / (order as u64);
        
        for g in 2..q {
            let candidate = mod_pow(g, exp, q);
            // Check it's primitive: candidate^(order/2) should be -1 (= q-1)
            let half = mod_pow(candidate, (order / 2) as u64, q);
            if half == q - 1 {
                return candidate;
            }
        }
        
        panic!("No primitive root found for q={}, order={}", q, order);
    }
    
    /// Forward NTT using DFT matrix
    pub fn ntt(&self, a: &[u64]) -> Vec<u64> {
        let mut result = vec![0u64; self.n];
        
        for k in 0..self.n {
            let mut sum = 0u128;
            for j in 0..self.n {
                let exp = (k * j) % self.n;
                let w = self.omega_powers[exp];
                sum += (a[j] as u128) * (w as u128);
            }
            result[k] = (sum % self.q as u128) as u64;
        }
        
        result
    }
    
    /// Inverse NTT using inverse DFT matrix
    pub fn intt(&self, a: &[u64]) -> Vec<u64> {
        let mut result = vec![0u64; self.n];
        
        for k in 0..self.n {
            let mut sum = 0u128;
            for j in 0..self.n {
                let exp = (k * j) % self.n;
                let w = self.omega_inv_powers[exp];
                sum += (a[j] as u128) * (w as u128);
            }
            result[k] = ((sum % self.q as u128) * self.n_inv as u128 % self.q as u128) as u64;
        }
        
        result
    }
    
    /// Multiply two polynomials using NTT (negacyclic convolution)
    /// This computes a * b mod (X^N + 1, q)
    pub fn multiply(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        assert_eq!(a.len(), self.n);
        assert_eq!(b.len(), self.n);
        
        // Step 1: Apply ψ-twist (convert to cyclic domain)
        let a_twisted: Vec<u64> = a.iter().enumerate()
            .map(|(i, &ai)| ((ai as u128 * self.psi_powers[i] as u128) % self.q as u128) as u64)
            .collect();
        
        let b_twisted: Vec<u64> = b.iter().enumerate()
            .map(|(i, &bi)| ((bi as u128 * self.psi_powers[i] as u128) % self.q as u128) as u64)
            .collect();
        
        // Step 2: Forward NTT
        let a_ntt = self.ntt(&a_twisted);
        let b_ntt = self.ntt(&b_twisted);
        
        // Step 3: Point-wise multiplication
        let c_ntt: Vec<u64> = a_ntt.iter().zip(b_ntt.iter())
            .map(|(&ai, &bi)| ((ai as u128 * bi as u128) % self.q as u128) as u64)
            .collect();
        
        // Step 4: Inverse NTT
        let c_twisted = self.intt(&c_ntt);
        
        // Step 5: Remove ψ-twist
        let result: Vec<u64> = c_twisted.iter().enumerate()
            .map(|(i, &ci)| ((ci as u128 * self.psi_inv_powers[i] as u128) % self.q as u128) as u64)
            .collect();
        
        result
    }
    
    /// Add two polynomials coefficient-wise
    pub fn add(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        assert_eq!(a.len(), self.n);
        assert_eq!(b.len(), self.n);
        
        a.iter().zip(b.iter())
            .map(|(&ai, &bi)| {
                let sum = ai as u128 + bi as u128;
                if sum >= self.q as u128 { (sum - self.q as u128) as u64 } else { sum as u64 }
            })
            .collect()
    }
    
    /// Subtract two polynomials coefficient-wise
    pub fn sub(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        assert_eq!(a.len(), self.n);
        assert_eq!(b.len(), self.n);
        
        a.iter().zip(b.iter())
            .map(|(&ai, &bi)| {
                if ai >= bi { ai - bi } else { self.q - bi + ai }
            })
            .collect()
    }
    
    /// Negate polynomial
    pub fn neg(&self, a: &[u64]) -> Vec<u64> {
        a.iter()
            .map(|&ai| if ai == 0 { 0 } else { self.q - ai })
            .collect()
    }
    
    /// Scalar multiply
    pub fn scalar_mul(&self, a: &[u64], scalar: u64) -> Vec<u64> {
        a.iter()
            .map(|&ai| ((ai as u128 * scalar as u128) % self.q as u128) as u64)
            .collect()
    }
}

/// Modular exponentiation
fn mod_pow(base: u64, exp: u64, modulus: u64) -> u64 {
    if modulus == 1 { return 0; }
    let mut result = 1u64;
    let mut base = base % modulus;
    let mut exp = exp;
    while exp > 0 {
        if exp & 1 == 1 {
            result = ((result as u128 * base as u128) % modulus as u128) as u64;
        }
        exp >>= 1;
        base = ((base as u128 * base as u128) % modulus as u128) as u64;
    }
    result
}

/// Modular inverse using extended Euclidean algorithm
fn mod_inverse(a: u64, m: u64) -> u64 {
    let mut mn = (m as i128, a as i128);
    let mut xy = (0i128, 1i128);
    while mn.1 != 0 {
        let q = mn.0 / mn.1;
        mn = (mn.1, mn.0 - q * mn.1);
        xy = (xy.1, xy.0 - q * xy.1);
    }
    while xy.0 < 0 { xy.0 += m as i128; }
    (xy.0 % m as i128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    
    const TEST_PRIME: u64 = 998244353;
    
    #[test]
    fn test_ntt_roundtrip() {
        let engine = NTTEngine::new(TEST_PRIME, 8);
        let original = vec![1, 2, 3, 4, 5, 6, 7, 8];
        
        // Apply twist + NTT + INTT + untwist
        let twisted: Vec<u64> = original.iter().enumerate()
            .map(|(i, &x)| ((x as u128 * engine.psi_powers[i] as u128) % engine.q as u128) as u64)
            .collect();
        
        let ntt_result = engine.ntt(&twisted);
        let intt_result = engine.intt(&ntt_result);
        
        let result: Vec<u64> = intt_result.iter().enumerate()
            .map(|(i, &x)| ((x as u128 * engine.psi_inv_powers[i] as u128) % engine.q as u128) as u64)
            .collect();
        
        assert_eq!(result, original);
    }
    
    #[test]
    fn test_ntt_multiply_correctness_small() {
        let engine = NTTEngine::new(TEST_PRIME, 8);
        
        let a = vec![1, 2, 3, 0, 0, 0, 0, 0];
        let b = vec![4, 5, 0, 0, 0, 0, 0, 0];
        
        let result = engine.multiply(&a, &b);
        
        // (1 + 2x + 3x^2) * (4 + 5x) = 4 + 13x + 22x^2 + 15x^3
        assert_eq!(result, vec![4, 13, 22, 15, 0, 0, 0, 0]);
    }
    
    #[test]
    fn test_ntt_negacyclic() {
        let engine = NTTEngine::new(TEST_PRIME, 4);
        
        // x^3 * x = x^4 = -1 in X^4 + 1
        let a = vec![0, 0, 0, 1];  // x^3
        let b = vec![0, 1, 0, 0];  // x
        
        let result = engine.multiply(&a, &b);
        
        assert_eq!(result, vec![TEST_PRIME - 1, 0, 0, 0]);
    }
    
    #[test]
    fn test_ntt_multiply_random() {
        let engine = NTTEngine::new(TEST_PRIME, 8);
        
        let a: Vec<u64> = (0..8).map(|i| (i * 12345) % TEST_PRIME).collect();
        let b: Vec<u64> = (0..8).map(|i| (i * 67890) % TEST_PRIME).collect();
        
        let result = engine.multiply(&a, &b);
        
        // Verify using schoolbook multiplication with negacyclic reduction
        let mut expected = vec![0i128; 8];
        for i in 0..8 {
            for j in 0..8 {
                let prod = a[i] as i128 * b[j] as i128;
                let idx = i + j;
                if idx < 8 {
                    expected[idx] += prod;
                } else {
                    expected[idx - 8] -= prod;
                }
            }
        }
        
        let expected: Vec<u64> = expected.iter().map(|&x| {
            let q = TEST_PRIME as i128;
            (((x % q) + q) % q) as u64
        }).collect();
        
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_polynomial_add() {
        let engine = NTTEngine::new(TEST_PRIME, 4);
        let result = engine.add(&[1, 2, 3, 4], &[5, 6, 7, 8]);
        assert_eq!(result, vec![6, 8, 10, 12]);
    }
    
    #[test]
    fn test_polynomial_sub() {
        let engine = NTTEngine::new(TEST_PRIME, 4);
        let result = engine.sub(&[10, 20, 30, 40], &[5, 6, 7, 8]);
        assert_eq!(result, vec![5, 14, 23, 32]);
    }
    
    #[test]
    fn test_ntt_benchmark_1024() {
        let engine = NTTEngine::new(TEST_PRIME, 1024);
        
        let a: Vec<u64> = (0..1024).map(|i| i % TEST_PRIME).collect();
        let b: Vec<u64> = (0..1024).map(|i| (i * 2) % TEST_PRIME).collect();
        
        let start = std::time::Instant::now();
        for _ in 0..100 {
            let _ = engine.multiply(&a, &b);
        }
        let elapsed = start.elapsed();
        
        println!("NTT 1024-point multiply x100: {:?}", elapsed);
    }
}
