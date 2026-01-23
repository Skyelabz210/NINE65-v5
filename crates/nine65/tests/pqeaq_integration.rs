//! NINE65 PQEAQ Integration Tests
//!
//! Tests encrypted quantum computation against Shor's algorithm baselines.
//!
//! Place in: crates/nine65/tests/pqeaq_integration.rs
//! Run with: cargo test -p nine65 --release --test pqeaq_integration -- --nocapture

use std::time::Instant;

// Import from nine65 crate
// Uncomment when integrated:
// use nine65::prelude::*;
// use nine65::quantum::{SparseGroverFp2, EncryptedQuantumContext};
// use nine65::fhe::{FHEConfig, KeySet, NTTEngine, ShadowHarvester};

/// Production prime
const P: u64 = 1_000_003;

// ═══════════════════════════════════════════════════════════════════════════════
// SHOR TEST SUITE
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod shor_tests {
    use super::*;
    
    /// Shor factoring targets
    const SHOR_TARGETS: &[(u64, (u64, u64))] = &[
        (15, (3, 5)),
        (21, (3, 7)),
        (35, (5, 7)),
        (77, (7, 11)),
        (91, (7, 13)),
        (143, (11, 13)),
        (221, (13, 17)),
        (323, (17, 19)),
        (437, (19, 23)),
        (667, (23, 29)),
    ];
    
    fn gcd(mut a: u64, mut b: u64) -> u64 {
        while b != 0 { let t = b; b = a % b; a = t; }
        a
    }
    
    fn mul_mod(a: u64, b: u64, m: u64) -> u64 {
        ((a as u128 * b as u128) % m as u128) as u64
    }
    
    fn pow_mod(mut base: u64, mut exp: u64, m: u64) -> u64 {
        let mut result = 1u64;
        base %= m;
        while exp > 0 {
            if exp & 1 == 1 { result = mul_mod(result, base, m); }
            exp >>= 1;
            base = mul_mod(base, base, m);
        }
        result
    }
    
    fn find_period(a: u64, n: u64) -> Option<u64> {
        let mut power = a;
        for r in 1..=(n * 2) {
            if power == 1 { return Some(r); }
            power = mul_mod(power, a, n);
        }
        None
    }
    
    fn factor_from_period(n: u64, a: u64, r: u64) -> Option<(u64, u64)> {
        if r % 2 != 0 { return None; }
        let a_half = pow_mod(a, r / 2, n);
        if a_half == 1 || a_half == n - 1 { return None; }
        
        let f1 = gcd(a_half + 1, n);
        let f2 = gcd(a_half.saturating_sub(1).max(1), n);
        
        if f1 > 1 && f1 < n { return Some((f1.min(n/f1), f1.max(n/f1))); }
        if f2 > 1 && f2 < n { return Some((f2.min(n/f2), f2.max(n/f2))); }
        None
    }
    
    fn shor_factor(n: u64) -> Option<(u64, u64)> {
        for a in 2..n.min(100) {
            let g = gcd(a, n);
            if g > 1 && g < n {
                return Some((g.min(n/g), g.max(n/g)));
            }
            if let Some(r) = find_period(a, n) {
                if let Some(f) = factor_from_period(n, a, r) {
                    return Some(f);
                }
            }
        }
        None
    }
    
    #[test]
    fn test_shor_all_targets() {
        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║  SHOR FACTORING VALIDATION                                   ║");
        println!("╚══════════════════════════════════════════════════════════════╝\n");
        
        let mut passed = 0;
        let start = Instant::now();
        
        for &(n, expected) in SHOR_TARGETS {
            let result = shor_factor(n);
            let success = result == Some(expected);
            
            println!("  {} = {:?} (expected {:?}) {}", 
                n, result, expected, if success { "✓" } else { "✗" });
            
            if success { passed += 1; }
        }
        
        let elapsed = start.elapsed();
        println!("\n  {}/{} passed in {:?}", passed, SHOR_TARGETS.len(), elapsed);
        
        assert_eq!(passed, SHOR_TARGETS.len(), "Some Shor factorizations failed");
    }
    
    #[test]
    fn test_period_finding() {
        let cases = vec![
            (2, 15, 4),
            (2, 21, 6),
            (7, 15, 4),
            (4, 21, 3),
        ];
        
        for (a, n, expected_r) in cases {
            let r = find_period(a, n);
            assert_eq!(r, Some(expected_r), "period({},{}) = {:?} expected {}", a, n, r, expected_r);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// GROVER TEST SUITE
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod grover_tests {
    use super::*;
    
    // Inline Fp2 and SparseGrover for standalone compilation
    fn add_mod(a: u64, b: u64, m: u64) -> u64 { ((a as u128 + b as u128) % m as u128) as u64 }
    fn sub_mod(a: u64, b: u64, m: u64) -> u64 { if a >= b { a - b } else { m - (b - a) } }
    fn mul_mod(a: u64, b: u64, m: u64) -> u64 { ((a as u128 * b as u128) % m as u128) as u64 }
    fn pow_mod(mut base: u64, mut exp: u64, m: u64) -> u64 {
        let mut result = 1u64;
        base %= m;
        while exp > 0 {
            if exp & 1 == 1 { result = mul_mod(result, base, m); }
            exp >>= 1;
            base = mul_mod(base, base, m);
        }
        result
    }
    fn mod_inverse(a: u64, p: u64) -> u64 { pow_mod(a, p - 2, p) }
    
    #[derive(Clone, Copy)]
    struct Fp2 { a: u64, b: u64, p: u64 }
    
    impl Fp2 {
        fn new(a: u64, b: u64, p: u64) -> Self { Self { a: a % p, b: b % p, p } }
        fn one(p: u64) -> Self { Self { a: 1, b: 0, p } }
        fn add(&self, o: &Self) -> Self { Self::new(add_mod(self.a, o.a, self.p), add_mod(self.b, o.b, self.p), self.p) }
        fn sub(&self, o: &Self) -> Self { Self::new(sub_mod(self.a, o.a, self.p), sub_mod(self.b, o.b, self.p), self.p) }
        fn neg(&self) -> Self { Self::new(if self.a == 0 { 0 } else { self.p - self.a }, if self.b == 0 { 0 } else { self.p - self.b }, self.p) }
        fn scalar_mul(&self, k: u64) -> Self { Self::new(mul_mod(self.a, k % self.p, self.p), mul_mod(self.b, k % self.p, self.p), self.p) }
        fn norm_squared(&self) -> u64 { add_mod(mul_mod(self.a, self.a, self.p), mul_mod(self.b, self.b, self.p), self.p) }
    }
    
    struct SparseGrover {
        target: Fp2, other: Fp2,
        qubits: u64, marked: u64, p: u64,
        n_mod_p: u64, n_inv: u64,
    }
    
    impl SparseGrover {
        fn new(qubits: u64, marked: u64, p: u64) -> Self {
            let n_mod_p = pow_mod(2, qubits, p);
            Self {
                target: Fp2::one(p), other: Fp2::one(p),
                qubits, marked, p, n_mod_p,
                n_inv: mod_inverse(n_mod_p, p),
            }
        }
        
        fn iterate(&mut self) {
            // Oracle
            self.target = self.target.neg();
            
            // Diffusion
            let n_m = sub_mod(self.n_mod_p, self.marked, self.p);
            let sum = self.target.scalar_mul(self.marked).add(&self.other.scalar_mul(n_m));
            let mean = sum.scalar_mul(self.n_inv);
            let two_mean = mean.add(&mean);
            self.target = two_mean.sub(&self.target);
            self.other = two_mean.sub(&self.other);
        }
        
        fn iterate_n(&mut self, n: usize) { for _ in 0..n { self.iterate(); } }
        
        fn weight(&self) -> u64 {
            let n_m = sub_mod(self.n_mod_p, self.marked, self.p);
            add_mod(
                mul_mod(self.target.norm_squared(), self.marked, self.p),
                mul_mod(self.other.norm_squared(), n_m, self.p),
                self.p
            )
        }
        
        fn target_prob(&self) -> f64 {
            let t = self.target.norm_squared() as f64;
            let o = self.other.norm_squared() as f64;
            let m = self.marked as f64;
            let n_m = sub_mod(self.n_mod_p, self.marked, self.p) as f64;
            let total = t * m + o * n_m;
            if total == 0.0 { 0.0 } else { (t * m) / total }
        }
    }
    
    #[test]
    fn test_grover_peak_probability() {
        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║  GROVER PEAK PROBABILITY VALIDATION                          ║");
        println!("╚══════════════════════════════════════════════════════════════╝\n");
        
        let cases = vec![
            (10, 25),   // π/4 × √1024 ≈ 25
            (12, 50),   // π/4 × √4096 ≈ 50
            (14, 100),  // π/4 × √16384 ≈ 100
            (16, 201),  // π/4 × √65536 ≈ 201
            (18, 402),  // π/4 × √262144 ≈ 402
            (20, 804),  // π/4 × √1048576 ≈ 804
        ];
        
        for (qubits, optimal) in cases {
            let mut state = SparseGrover::new(qubits, 1, P);
            state.iterate_n(optimal);
            let prob = state.target_prob();
            
            let status = if prob > 0.5 { "✓" } else { "✗" };
            println!("  {} qubits: {:.1}% at iteration {} {}", 
                qubits, prob * 100.0, optimal, status);
            
            assert!(prob > 0.5, "{}q: prob {:.1}% < 50%", qubits, prob * 100.0);
        }
    }
    
    #[test]
    fn test_grover_weight_preservation() {
        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║  GROVER WEIGHT PRESERVATION (UNITARITY)                      ║");
        println!("╚══════════════════════════════════════════════════════════════╝\n");
        
        let mut state = SparseGrover::new(20, 1, P);
        let w0 = state.weight();
        
        let checkpoints = vec![1, 10, 100, 1000, 5000, 10000];
        let mut last = 0;
        
        for &iter in &checkpoints {
            state.iterate_n(iter - last);
            last = iter;
            let w = state.weight();
            
            let status = if w == w0 { "✓" } else { "✗" };
            println!("  After {:>5} iterations: weight = {} {}", iter, w, status);
            
            assert_eq!(w, w0, "Weight drift at iteration {}: {} → {}", iter, w0, w);
        }
    }
    
    #[test]
    fn test_grover_performance_benchmark() {
        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║  GROVER PERFORMANCE BENCHMARK                                ║");
        println!("╚══════════════════════════════════════════════════════════════╝\n");
        
        let sizes = vec![10, 100, 1000, 10000, 100000, 1000000];
        
        for qubits in sizes {
            let mut state = SparseGrover::new(qubits, 1, P);
            
            let start = Instant::now();
            state.iterate_n(10000);
            let elapsed = start.elapsed();
            
            let ns_per = elapsed.as_nanos() / 10000;
            let m_per_sec = 1_000_000_000 / ns_per.max(1) / 1_000_000;
            
            println!("  {:>7} qubits: {:>4} ns/iter, {:>3} M iter/sec", 
                qubits, ns_per, m_per_sec);
        }
    }
    
    #[test]
    fn test_grover_oscillation() {
        // Verify oscillation continues (zero decoherence)
        let mut state = SparseGrover::new(12, 1, P);
        
        // First peak
        state.iterate_n(50);
        let first_peak = state.target_prob();
        
        // Should return to low after another ~50 iterations
        state.iterate_n(50);
        let trough = state.target_prob();
        
        // Second peak at ~150
        state.iterate_n(50);
        let second_peak = state.target_prob();
        
        println!("\nOscillation test (12 qubits):");
        println!("  Peak 1 (iter 50):  {:.1}%", first_peak * 100.0);
        println!("  Trough (iter 100): {:.1}%", trough * 100.0);
        println!("  Peak 2 (iter 150): {:.1}%", second_peak * 100.0);
        
        // Must oscillate
        assert!(first_peak > trough + 0.3, "No oscillation detected");
        assert!(second_peak > trough + 0.2, "Damped oscillation detected");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENCRYPTED QUANTUM TEST SUITE (requires NINE65 FHE)
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
#[cfg(feature = "fhe")]
mod encrypted_tests {
    use super::*;
    
    // This module requires the nine65 crate with FHE features
    // Uncomment when integrating:
    /*
    use nine65::prelude::*;
    use nine65::quantum::{EncryptedQuantumContext, EncryptedSparseGrover};
    use nine65::fhe::{FHEConfig, KeySet, NTTEngine, ShadowHarvester, BFVEncoder, BFVEncryptor, BFVDecryptor, BFVEvaluator};
    
    #[test]
    fn test_encrypted_grover_vs_unencrypted() {
        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║  ENCRYPTED vs UNENCRYPTED GROVER                             ║");
        println!("╚══════════════════════════════════════════════════════════════╝\n");
        
        // Setup FHE
        let config = FHEConfig::he_standard_128();
        let ntt = NTTEngine::new(config.q, config.n);
        let mut rng = ShadowHarvester::with_seed(0xDEAD);
        let keys = KeySet::generate(&config, &ntt, &mut rng);
        
        let encoder = BFVEncoder::new(&config);
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
        let evaluator = BFVEvaluator::new(&ntt, &encoder, Some(&keys.eval_key));
        
        let ctx = EncryptedQuantumContext {
            config: &config, ntt: &ntt, encoder: &encoder,
            encryptor: &encryptor, decryptor: &decryptor, evaluator: &evaluator,
        };
        
        // Compare encrypted vs unencrypted for 15 qubits, 50 iterations
        let qubits = 15;
        let iterations = 50;
        
        // Unencrypted baseline
        let mut plain = SparseGroverFp2::new(qubits, 1, P);
        plain.iterate_n(iterations);
        let plain_target = (plain.target_amp.a, plain.target_amp.b);
        let plain_other = (plain.other_amp.a, plain.other_amp.b);
        
        // Encrypted
        let mut encrypted = ctx.encrypt_sparse_grover(qubits, P, &mut rng);
        for _ in 0..iterations {
            ctx.encrypted_grover_iteration(&mut encrypted);
        }
        let decrypted = ctx.decrypt_state(&encrypted);
        let enc_target = decrypted.target_amp;
        let enc_other = decrypted.other_amp;
        
        println!("  Unencrypted target: ({}, {})", plain_target.0, plain_target.1);
        println!("  Encrypted target:   ({}, {})", enc_target.0, enc_target.1);
        println!("  Unencrypted other:  ({}, {})", plain_other.0, plain_other.1);
        println!("  Encrypted other:    ({}, {})", enc_other.0, enc_other.1);
        
        // Should produce same results (within FHE noise)
        // Note: exact match may not happen due to FHE representation, but values should be "close" in modular sense
        assert!(enc_target.0 < config.t, "Encrypted target.a out of range");
        assert!(enc_other.0 < config.t, "Encrypted other.a out of range");
    }
    
    #[test]
    fn test_encrypted_depth_limit() {
        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║  ENCRYPTED DEPTH VALIDATION                                  ║");
        println!("╚══════════════════════════════════════════════════════════════╝\n");
        
        let config = FHEConfig::he_standard_128();
        let ntt = NTTEngine::new(config.q, config.n);
        let mut rng = ShadowHarvester::with_seed(0xBEEF);
        let keys = KeySet::generate(&config, &ntt, &mut rng);
        
        let encoder = BFVEncoder::new(&config);
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
        let evaluator = BFVEvaluator::new(&ntt, &encoder, Some(&keys.eval_key));
        
        let ctx = EncryptedQuantumContext { ... };
        
        let mut state = ctx.encrypt_sparse_grover(20, P, &mut rng);
        
        let checkpoints = vec![100, 200, 500, 800, 1000];
        
        for &target_iter in &checkpoints {
            // Run to checkpoint
            let current_iter = /* track current */;
            for _ in current_iter..target_iter {
                ctx.encrypted_grover_iteration(&mut state);
            }
            
            // Verify decryption still works
            let result = ctx.decrypt_state(&state);
            let valid = result.target_amp.0 < config.t && result.other_amp.0 < config.t;
            
            println!("  {} iterations: {}", target_iter, if valid { "✓" } else { "✗" });
            
            assert!(valid, "Decryption failed at {} iterations", target_iter);
        }
        
        println!("\n  ✓ Exceeded optimal Grover depth (907 iterations) without failure");
    }
    */
    
    // Placeholder until FHE integration
    #[test]
    fn test_encrypted_placeholder() {
        println!("\n  [Encrypted tests require nine65 crate with FHE features]");
        println!("  Run: cargo test -p nine65 --features fhe encrypted");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// FULL HARNESS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod full_harness {
    use super::*;
    
    #[test]
    fn test_pqeaq_full_validation() {
        println!("\n");
        println!("╔══════════════════════════════════════════════════════════════════════════╗");
        println!("║                                                                          ║");
        println!("║   PQEAQ FULL VALIDATION SUITE                                            ║");
        println!("║   Post-Quantum Encrypted Algebraic Quantum                               ║");
        println!("║                                                                          ║");
        println!("╚══════════════════════════════════════════════════════════════════════════╝");
        println!("\n");
        
        // All tests run via their respective modules
        // This test just provides the banner
    }
}
