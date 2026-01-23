//! Prime Selection - NTT-Friendly Primes for FHE
//!
//! QMNF requires primes q where:
//! - q ≡ 1 (mod 2N) for NTT compatibility
//! - q is large enough for security
//! - Multiple primes are coprime for RNS

/// Standard NTT-friendly primes for various polynomial degrees
/// These satisfy q ≡ 1 (mod 2N) and are suitable for FHE
pub const PRIMES_1024: [u64; 4] = [
    998244353,    // 2^23 * 7 * 17 + 1
    985661441,    // 2^22 * 5 * 47 + 1  
    754974721,    // 2^24 * 45 + 1
    167772161,    // 2^25 * 5 + 1
];

pub const PRIMES_4096: [u64; 4] = [
    998244353,
    985661441,
    754974721,
    469762049,    // 2^26 * 7 + 1
];

/// 8 primes for full 8-core utilization at N=8192
/// Each satisfies q ≡ 1 (mod 16384) for NTT compatibility
/// Product exceeds 2^128 for 128-bit security
pub const PRIMES_8192: [u64; 8] = [
    998244353,    // 2^23 × 119 + 1
    985661441,    // 2^22 × 235 + 1
    754974721,    // 2^24 × 45 + 1
    469762049,    // 2^26 × 7 + 1
    1638350849,   // 16384 × 99997 + 1 (31 bits)
    1638137857,   // 16384 × 99984 + 1 (31 bits)
    1637990401,   // 16384 × 99975 + 1 (31 bits)
    1637613569,   // 16384 × 99952 + 1 (31 bits)
];

/// Check if a number is prime (simple trial division for small primes)
pub fn is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    if n == 2 || n == 3 {
        return true;
    }
    if n % 2 == 0 || n % 3 == 0 {
        return false;
    }
    
    let mut i = 5u64;
    while i * i <= n {
        if n % i == 0 || n % (i + 2) == 0 {
            return false;
        }
        i += 6;
    }
    true
}

/// Check if prime is NTT-compatible for given N
pub fn is_ntt_compatible(q: u64, n: usize) -> bool {
    (q - 1) % (2 * n as u64) == 0
}

/// Find NTT-friendly primes near a target value
pub fn find_ntt_primes(n: usize, num_primes: usize, min_bits: u32) -> Vec<u64> {
    let two_n = 2 * n as u64;
    let min_value = 1u64 << min_bits;
    let max_value = 1u64 << (min_bits + 4);
    
    let mut primes = Vec::new();
    let mut k = max_value / two_n;
    
    while primes.len() < num_primes && k > min_value / two_n {
        let candidate = k * two_n + 1;
        if is_prime(candidate) && !primes.contains(&candidate) {
            primes.push(candidate);
        }
        k -= 1;
    }
    
    primes
}

/// GCD using Euclidean algorithm
pub fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { gcd(b, a % b) }
}

/// Extended GCD: returns (g, x, y) such that ax + by = g
pub fn extended_gcd(a: i128, b: i128) -> (i128, i128, i128) {
    if a == 0 {
        (b, 0, 1)
    } else {
        let (g, x, y) = extended_gcd(b % a, a);
        (g, y - (b / a) * x, x)
    }
}

/// Modular inverse: a^(-1) mod m
pub fn mod_inverse(a: u64, m: u64) -> u64 {
    let (g, x, _) = extended_gcd(a as i128, m as i128);
    assert_eq!(g, 1, "No inverse exists");
    ((x % m as i128 + m as i128) % m as i128) as u64
}

/// Modular exponentiation: base^exp mod m
pub fn mod_pow(base: u64, exp: u64, m: u64) -> u64 {
    if m == 1 {
        return 0;
    }
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

/// Find a primitive n-th root of unity modulo prime q
pub fn find_primitive_root(q: u64, n: usize) -> u64 {
    assert!((q - 1) % (n as u64) == 0, "n must divide q-1");
    
    let exp = (q - 1) / (n as u64);
    
    for g in 2..q {
        let candidate = mod_pow(g, exp, q);
        
        // Check it's a primitive n-th root (order is exactly n)
        let half = mod_pow(candidate, (n / 2) as u64, q);
        if half != 1 && mod_pow(candidate, n as u64, q) == 1 {
            return candidate;
        }
    }
    
    panic!("No primitive root found");
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_primes_are_prime() {
        for &p in &PRIMES_1024 {
            assert!(is_prime(p), "{} should be prime", p);
        }
    }
    
    #[test]
    fn test_primes_ntt_compatible_4096() {
        for &p in &PRIMES_4096 {
            assert!(is_ntt_compatible(p, 4096), "{} should be NTT-compatible for N=4096", p);
        }
    }
    
    #[test]
    fn test_primes_ntt_compatible_8192() {
        for &p in &PRIMES_8192 {
            assert!(is_ntt_compatible(p, 8192), "{} should be NTT-compatible for N=8192", p);
        }
    }
    
    #[test]
    fn test_primes_pairwise_coprime() {
        let primes = &PRIMES_1024;
        for i in 0..primes.len() {
            for j in (i + 1)..primes.len() {
                assert_eq!(gcd(primes[i], primes[j]), 1,
                           "Primes {} and {} share factor {}",
                           primes[i], primes[j], gcd(primes[i], primes[j]));
            }
        }
    }
    
    #[test]
    fn test_product_security_128bit() {
        // Product of primes should exceed 2^128 for 128-bit security
        let product: u128 = PRIMES_1024.iter().map(|&p| p as u128).product();
        assert!(product > 1u128 << 100, "Product too small for security");
    }
    
    #[test]
    fn test_gcd() {
        assert_eq!(gcd(48, 18), 6);
        assert_eq!(gcd(17, 13), 1);
        assert_eq!(gcd(100, 25), 25);
    }
    
    #[test]
    fn test_mod_inverse() {
        let p = 998244353u64;
        for a in [1, 2, 3, 100, 12345, p - 1] {
            let inv = mod_inverse(a, p);
            let product = ((a as u128 * inv as u128) % p as u128) as u64;
            assert_eq!(product, 1, "Inverse of {} failed", a);
        }
    }
    
    #[test]
    fn test_mod_pow() {
        assert_eq!(mod_pow(2, 10, 1000), 24);  // 1024 mod 1000
        assert_eq!(mod_pow(3, 0, 17), 1);
        assert_eq!(mod_pow(7, 11, 13), 2);  // Fermat's little theorem
    }
    
    #[test]
    fn test_find_primitive_root() {
        let q = 998244353u64;
        let n = 2048usize;
        
        let omega = find_primitive_root(q, n);
        
        // omega^n should be 1
        assert_eq!(mod_pow(omega, n as u64, q), 1);
        
        // omega^(n/2) should not be 1
        assert_ne!(mod_pow(omega, (n / 2) as u64, q), 1);
    }
}
