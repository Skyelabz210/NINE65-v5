//! Secure Entropy Module - OS CSPRNG Wrapper
//!
//! SECURITY CRITICAL: This module provides cryptographically secure
//! random number generation using the operating system's CSPRNG.
//!
//! Use this for:
//! - Secret key generation
//! - Public key randomness (the 'a' polynomial)
//! - Any security-critical random values
//!
//! Do NOT use Shadow Entropy for these operations.
//!
//! Added: December 2024 Cryptographic Audit

use getrandom::getrandom;

/// Get cryptographically secure random bytes from OS
///
/// # Panics
/// Panics if the OS CSPRNG fails (should never happen on supported platforms)
#[inline]
pub fn secure_bytes(buf: &mut [u8]) {
    getrandom(buf).expect("OS CSPRNG failure - cannot proceed safely");
}

/// Generate a cryptographically secure random u64
#[inline]
pub fn secure_u64() -> u64 {
    let mut buf = [0u8; 8];
    secure_bytes(&mut buf);
    u64::from_le_bytes(buf)
}

/// Generate a cryptographically secure random u128
#[inline]
pub fn secure_u128() -> u128 {
    let mut buf = [0u8; 16];
    secure_bytes(&mut buf);
    u128::from_le_bytes(buf)
}

/// Generate a cryptographically secure random u64 in range [0, bound)
///
/// Uses rejection sampling to avoid modulo bias.
#[inline]
pub fn secure_u64_bounded(bound: u64) -> u64 {
    if bound == 0 {
        return 0;
    }
    if bound == 1 {
        return 0;
    }
    
    // Rejection sampling to avoid modulo bias
    // threshold is the largest multiple of bound that fits in u64
    let threshold = u64::MAX - (u64::MAX % bound);
    
    loop {
        let val = secure_u64();
        if val < threshold {
            return val % bound;
        }
        // Rejection probability is at most 50%, expected iterations < 2
    }
}

/// Generate a cryptographically secure ternary value {-1, 0, 1}
///
/// Returns values with equal probability (1/3 each).
#[inline]
pub fn secure_ternary() -> i64 {
    // Use rejection sampling for uniform distribution over 3 values
    loop {
        let r = secure_u64() % 4;  // 0, 1, 2, 3
        if r < 3 {
            return (r as i64) - 1;  // -1, 0, 1
        }
        // Reject r=3, try again (25% rejection rate)
    }
}

/// Generate a CBD(η) sample using secure randomness
///
/// Centered Binomial Distribution: sum of η coin flips minus η coin flips
/// Range: [-η, η], variance: η/2
#[inline]
pub fn secure_cbd(eta: usize) -> i64 {
    let mut sum = 0i64;
    
    // Each iteration: add one bit, subtract another bit
    // This gives CBD with parameter η
    for _ in 0..eta {
        let bits = secure_u64();
        let a = (bits & 1) as i64;
        let b = ((bits >> 1) & 1) as i64;
        sum += a - b;
    }
    
    sum
}

/// Generate a vector of CBD(η) samples
pub fn secure_cbd_vector(n: usize, eta: usize) -> Vec<i64> {
    (0..n).map(|_| secure_cbd(eta)).collect()
}

/// Generate a vector of uniform random values in [0, bound)
pub fn secure_uniform_vector(n: usize, bound: u64) -> Vec<u64> {
    (0..n).map(|_| secure_u64_bounded(bound)).collect()
}

/// Generate a ternary vector {-1, 0, 1}^n
pub fn secure_ternary_vector(n: usize) -> Vec<i64> {
    (0..n).map(|_| secure_ternary()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_bytes() {
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        
        secure_bytes(&mut buf1);
        secure_bytes(&mut buf2);
        
        // Should be different (probability of same: 2^-256)
        assert_ne!(buf1, buf2, "CSPRNG produced identical outputs");
        
        // Should have non-zero entropy
        assert!(buf1.iter().any(|&b| b != 0), "CSPRNG produced all zeros");
    }
    
    #[test]
    fn test_secure_u64_bounded() {
        // Test various bounds
        for bound in [2, 3, 7, 100, 65537, 998244353] {
            for _ in 0..100 {
                let val = secure_u64_bounded(bound);
                assert!(val < bound, "Value {} >= bound {}", val, bound);
            }
        }
    }
    
    #[test]
    fn test_secure_ternary_distribution() {
        let samples: Vec<i64> = (0..10000).map(|_| secure_ternary()).collect();
        
        // All values should be in {-1, 0, 1}
        for &s in &samples {
            assert!(s >= -1 && s <= 1, "Ternary out of range: {}", s);
        }
        
        // Check rough uniformity (each should be ~3333)
        let neg_ones = samples.iter().filter(|&&s| s == -1).count();
        let zeros = samples.iter().filter(|&&s| s == 0).count();
        let pos_ones = samples.iter().filter(|&&s| s == 1).count();
        
        // Allow 20% deviation from expected
        assert!(neg_ones > 2500 && neg_ones < 4200, "Bad -1 count: {}", neg_ones);
        assert!(zeros > 2500 && zeros < 4200, "Bad 0 count: {}", zeros);
        assert!(pos_ones > 2500 && pos_ones < 4200, "Bad 1 count: {}", pos_ones);
    }
    
    #[test]
    fn test_secure_cbd() {
        let eta = 3;
        let samples: Vec<i64> = (0..10000).map(|_| secure_cbd(eta)).collect();
        
        // All values should be in [-η, η]
        for &s in &samples {
            assert!(s >= -(eta as i64) && s <= eta as i64, 
                    "CBD out of range: {} not in [{}, {}]", s, -(eta as i64), eta);
        }
        
        // Check variance is approximately η/2
        let mean: f64 = samples.iter().map(|&s| s as f64).sum::<f64>() / samples.len() as f64;
        let variance: f64 = samples.iter()
            .map(|&s| (s as f64 - mean).powi(2))
            .sum::<f64>() / samples.len() as f64;
        
        let expected_variance = eta as f64 / 2.0;
        assert!((variance - expected_variance).abs() < 0.5,
                "CBD variance {} far from expected {}", variance, expected_variance);
    }
    
    #[test]
    fn test_secure_vectors() {
        let n = 1024;
        let bound = 998244353u64;
        
        let uniform = secure_uniform_vector(n, bound);
        assert_eq!(uniform.len(), n);
        assert!(uniform.iter().all(|&v| v < bound));
        
        let ternary = secure_ternary_vector(n);
        assert_eq!(ternary.len(), n);
        assert!(ternary.iter().all(|&v| v >= -1 && v <= 1));
        
        let cbd = secure_cbd_vector(n, 3);
        assert_eq!(cbd.len(), n);
        assert!(cbd.iter().all(|&v| v >= -3 && v <= 3));
    }
}
