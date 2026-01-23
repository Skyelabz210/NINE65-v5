//! Montgomery Arithmetic - Gen 2 Division-Free Modular Multiplication
//! 
//! QMNF Innovation: Persistent Montgomery representation eliminates
//! the 70-year boundary conversion overhead by staying in residue space.

/// Montgomery context for a specific modulus
#[derive(Clone, Debug)]
pub struct MontgomeryContext {
    /// The modulus q
    pub q: u64,
    /// R = 2^64 mod q (implicit)
    pub r: u128,
    /// R^2 mod q for fast conversion to Montgomery form
    pub r2: u64,
    /// -q^(-1) mod 2^64
    pub q_inv_neg: u64,
}

impl MontgomeryContext {
    /// Create a new Montgomery context for modulus q
    pub fn new(q: u64) -> Self {
        // R = 2^64
        let r: u128 = 1u128 << 64;
        
        // Compute R mod q
        let _r_mod_q = (r % (q as u128)) as u64;
        
        // Compute R^2 mod q
        let r2 = Self::compute_r2(q);
        
        // Compute -q^(-1) mod 2^64 using extended Euclidean algorithm
        let q_inv_neg = Self::compute_q_inv_neg(q);
        
        Self { q, r, r2, q_inv_neg }
    }
    
    /// Compute R^2 mod q
    fn compute_r2(q: u64) -> u64 {
        // R^2 = 2^128 mod q
        // We compute this by repeated squaring: (2^64 mod q)^2 mod q
        let r_mod_q = ((1u128 << 64) % (q as u128)) as u64;
        ((r_mod_q as u128 * r_mod_q as u128) % (q as u128)) as u64
    }
    
    /// Compute -q^(-1) mod 2^64 using Newton's method
    fn compute_q_inv_neg(q: u64) -> u64 {
        // Newton iteration: x_{n+1} = x_n * (2 - q * x_n) mod 2^64
        // Starting with x_0 = 1 (works for odd q)
        let mut x: u64 = 1;
        for _ in 0..6 {
            x = x.wrapping_mul(2u64.wrapping_sub(q.wrapping_mul(x)));
        }
        // Return -q^(-1) mod 2^64
        x.wrapping_neg()
    }
    
    /// Convert to Montgomery form: a -> aR mod q
    #[inline(always)]
    pub fn to_montgomery(&self, a: u64) -> u64 {
        self.montgomery_mul(a, self.r2)
    }
    
    /// Convert from Montgomery form: aR -> a mod q
    #[inline(always)]
    pub fn from_montgomery(&self, a_mont: u64) -> u64 {
        self.montgomery_reduce(a_mont as u128)
    }
    
    /// Montgomery multiplication: (aR * bR) / R mod q = abR mod q
    #[inline(always)]
    pub fn montgomery_mul(&self, a: u64, b: u64) -> u64 {
        let t = (a as u128) * (b as u128);
        self.montgomery_reduce(t)
    }
    
    /// Montgomery reduction: t / R mod q
    /// REDC algorithm - no division, only multiplication and shifts
    #[inline(always)]
    pub fn montgomery_reduce(&self, t: u128) -> u64 {
        // m = (t mod R) * q_inv_neg mod R
        let t_lo = t as u64;
        let m = t_lo.wrapping_mul(self.q_inv_neg);
        
        // t = (t + m * q) / R
        let mq = (m as u128) * (self.q as u128);
        let result = ((t.wrapping_add(mq)) >> 64) as u64;
        
        // Final reduction if needed
        if result >= self.q {
            result - self.q
        } else {
            result
        }
    }
    
    /// Montgomery squaring (slightly optimized)
    #[inline(always)]
    pub fn montgomery_square(&self, a: u64) -> u64 {
        self.montgomery_mul(a, a)
    }
    
    /// Montgomery exponentiation: a^e mod q (in Montgomery form)
    pub fn montgomery_pow(&self, base: u64, exp: u64) -> u64 {
        if exp == 0 {
            return self.to_montgomery(1);
        }
        
        let mut result = self.to_montgomery(1);
        let mut base = base;
        let mut e = exp;
        
        while e > 0 {
            if e & 1 == 1 {
                result = self.montgomery_mul(result, base);
            }
            base = self.montgomery_square(base);
            e >>= 1;
        }
        
        result
    }
    
    /// Add two Montgomery form numbers
    #[inline(always)]
    pub fn montgomery_add(&self, a: u64, b: u64) -> u64 {
        let sum = a as u128 + b as u128;
        if sum >= self.q as u128 {
            (sum - self.q as u128) as u64
        } else {
            sum as u64
        }
    }
    
    /// Subtract two Montgomery form numbers
    #[inline(always)]
    pub fn montgomery_sub(&self, a: u64, b: u64) -> u64 {
        if a >= b {
            a - b
        } else {
            self.q - b + a
        }
    }
    
    /// Negate in Montgomery form
    #[inline(always)]
    pub fn montgomery_neg(&self, a: u64) -> u64 {
        if a == 0 {
            0
        } else {
            self.q - a
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    const TEST_PRIME: u64 = 998244353;
    
    #[test]
    fn test_montgomery_roundtrip() {
        let ctx = MontgomeryContext::new(TEST_PRIME);
        
        for a in [0, 1, 2, 100, 12345, TEST_PRIME - 1] {
            let mont = ctx.to_montgomery(a);
            let back = ctx.from_montgomery(mont);
            assert_eq!(back, a, "Roundtrip failed for {}", a);
        }
    }
    
    #[test]
    fn test_montgomery_mul() {
        let ctx = MontgomeryContext::new(TEST_PRIME);
        
        let a = 12345u64;
        let b = 67890u64;
        let expected = ((a as u128 * b as u128) % TEST_PRIME as u128) as u64;
        
        let a_mont = ctx.to_montgomery(a);
        let b_mont = ctx.to_montgomery(b);
        let result_mont = ctx.montgomery_mul(a_mont, b_mont);
        let result = ctx.from_montgomery(result_mont);
        
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_montgomery_pow() {
        let ctx = MontgomeryContext::new(TEST_PRIME);
        
        let base = 3u64;
        let exp = 100u64;
        
        // Compute expected result the slow way
        let mut expected = 1u64;
        for _ in 0..exp {
            expected = ((expected as u128 * base as u128) % TEST_PRIME as u128) as u64;
        }
        
        let base_mont = ctx.to_montgomery(base);
        let result_mont = ctx.montgomery_pow(base_mont, exp);
        let result = ctx.from_montgomery(result_mont);
        
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_montgomery_add_sub() {
        let ctx = MontgomeryContext::new(TEST_PRIME);
        
        let a = 12345u64;
        let b = 67890u64;
        
        let a_mont = ctx.to_montgomery(a);
        let b_mont = ctx.to_montgomery(b);
        
        // Test add
        let sum_mont = ctx.montgomery_add(a_mont, b_mont);
        let sum = ctx.from_montgomery(sum_mont);
        assert_eq!(sum, (a + b) % TEST_PRIME);
        
        // Test sub
        let diff_mont = ctx.montgomery_sub(b_mont, a_mont);
        let diff = ctx.from_montgomery(diff_mont);
        assert_eq!(diff, (b - a) % TEST_PRIME);
    }
    
    #[test]
    fn test_montgomery_benchmark() {
        let ctx = MontgomeryContext::new(TEST_PRIME);
        let a = ctx.to_montgomery(12345);
        let b = ctx.to_montgomery(67890);
        
        let start = std::time::Instant::now();
        let mut result = a;
        for _ in 0..100_000 {
            result = ctx.montgomery_mul(result, b);
        }
        let elapsed = start.elapsed();
        
        println!("Montgomery 100k muls: {:?} (result={})", elapsed, ctx.from_montgomery(result));
        // Should be < 5ms for 100k operations
    }
}
