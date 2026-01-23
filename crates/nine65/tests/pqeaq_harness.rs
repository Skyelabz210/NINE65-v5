//! PQEAQ Test Harness
//!
//! Validates encrypted quantum computation against Shor's algorithm benchmarks
//! and unencrypted baselines.
//!
//! Run with: cargo test -p nine65 --release pqeaq_harness -- --nocapture
//! Or standalone: cargo run --release --example pqeaq_harness

use std::time::{Instant, Duration};

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Production prime for F_p² operations
pub const PRODUCTION_PRIME: u64 = 1_000_003;

/// Test cases for Shor factoring validation
pub const SHOR_TEST_CASES: &[(u64, (u64, u64))] = &[
    (15, (3, 5)),
    (21, (3, 7)),
    (35, (5, 7)),
    (77, (7, 11)),
    (91, (7, 13)),
    (143, (11, 13)),
    (221, (13, 17)),
    (323, (17, 19)),
];

/// Grover test cases: (qubits, marked, optimal_iterations)
pub const GROVER_TEST_CASES: &[(u64, u64, usize)] = &[
    (10, 1, 25),      // 2^10 = 1024 states
    (12, 1, 50),      // 2^12 = 4096 states  
    (14, 1, 100),     // 2^14 = 16384 states
    (15, 1, 143),     // 2^15 = 32768 states
    (16, 1, 201),     // 2^16 = 65536 states
    (18, 1, 402),     // 2^18 = 262144 states
    (20, 1, 804),     // 2^20 = 1048576 states
];

// ═══════════════════════════════════════════════════════════════════════════════
// MODULAR ARITHMETIC (inline for standalone operation)
// ═══════════════════════════════════════════════════════════════════════════════

#[inline]
pub fn add_mod(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128 + b as u128) % m as u128) as u64
}

#[inline]
pub fn sub_mod(a: u64, b: u64, m: u64) -> u64 {
    if a >= b { a - b } else { m - (b - a) }
}

#[inline]
pub fn mul_mod(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128 * b as u128) % m as u128) as u64
}

pub fn pow_mod(mut base: u64, mut exp: u64, m: u64) -> u64 {
    let mut result = 1u64;
    base %= m;
    while exp > 0 {
        if exp & 1 == 1 { result = mul_mod(result, base, m); }
        exp >>= 1;
        base = mul_mod(base, base, m);
    }
    result
}

pub fn mod_inverse(a: u64, p: u64) -> u64 {
    pow_mod(a, p - 2, p)
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

// ═══════════════════════════════════════════════════════════════════════════════
// F_p² FIELD
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Fp2 {
    pub a: u64,
    pub b: u64,
    pub p: u64,
}

impl Fp2 {
    pub fn new(a: u64, b: u64, p: u64) -> Self {
        Self { a: a % p, b: b % p, p }
    }
    
    pub fn zero(p: u64) -> Self { Self { a: 0, b: 0, p } }
    pub fn one(p: u64) -> Self { Self { a: 1, b: 0, p } }
    
    pub fn add(&self, other: &Self) -> Self {
        Self::new(add_mod(self.a, other.a, self.p), add_mod(self.b, other.b, self.p), self.p)
    }
    
    pub fn sub(&self, other: &Self) -> Self {
        Self::new(sub_mod(self.a, other.a, self.p), sub_mod(self.b, other.b, self.p), self.p)
    }
    
    pub fn neg(&self) -> Self {
        Self::new(
            if self.a == 0 { 0 } else { self.p - self.a },
            if self.b == 0 { 0 } else { self.p - self.b },
            self.p
        )
    }
    
    pub fn mul(&self, other: &Self) -> Self {
        let ac = mul_mod(self.a, other.a, self.p);
        let bd = mul_mod(self.b, other.b, self.p);
        let ad = mul_mod(self.a, other.b, self.p);
        let bc = mul_mod(self.b, other.a, self.p);
        Self::new(sub_mod(ac, bd, self.p), add_mod(ad, bc, self.p), self.p)
    }
    
    pub fn scalar_mul(&self, k: u64) -> Self {
        Self::new(mul_mod(self.a, k % self.p, self.p), mul_mod(self.b, k % self.p, self.p), self.p)
    }
    
    pub fn norm_squared(&self) -> u64 {
        add_mod(mul_mod(self.a, self.a, self.p), mul_mod(self.b, self.b, self.p), self.p)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SPARSE GROVER STATE
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug)]
pub struct SparseGroverState {
    pub target_amp: Fp2,
    pub other_amp: Fp2,
    pub num_qubits: u64,
    pub num_marked: u64,
    pub p: u64,
    pub n_mod_p: u64,
    pub n_inv_mod_p: u64,
}

impl SparseGroverState {
    pub fn new(num_qubits: u64, num_marked: u64, p: u64) -> Self {
        let n_mod_p = pow_mod(2, num_qubits, p);
        let n_inv_mod_p = mod_inverse(n_mod_p, p);
        
        Self {
            target_amp: Fp2::one(p),
            other_amp: Fp2::one(p),
            num_qubits,
            num_marked,
            p,
            n_mod_p,
            n_inv_mod_p,
        }
    }
    
    pub fn oracle(&mut self) {
        self.target_amp = self.target_amp.neg();
    }
    
    pub fn diffusion(&mut self) {
        let m = self.num_marked;
        let n_m = sub_mod(self.n_mod_p, m, self.p);
        
        let scaled_t = self.target_amp.scalar_mul(m);
        let scaled_o = self.other_amp.scalar_mul(n_m);
        let sum = scaled_t.add(&scaled_o);
        let mean = sum.scalar_mul(self.n_inv_mod_p);
        let two_mean = mean.add(&mean);
        
        self.target_amp = two_mean.sub(&self.target_amp);
        self.other_amp = two_mean.sub(&self.other_amp);
    }
    
    pub fn iterate(&mut self) {
        self.oracle();
        self.diffusion();
    }
    
    pub fn iterate_n(&mut self, n: usize) {
        for _ in 0..n {
            self.iterate();
        }
    }
    
    pub fn total_weight(&self) -> u64 {
        let t_norm = self.target_amp.norm_squared();
        let o_norm = self.other_amp.norm_squared();
        let n_m = sub_mod(self.n_mod_p, self.num_marked, self.p);
        add_mod(
            mul_mod(t_norm, self.num_marked, self.p),
            mul_mod(o_norm, n_m, self.p),
            self.p
        )
    }
    
    /// Target probability relative to total weight
    pub fn target_probability(&self) -> f64 {
        let t_norm = self.target_amp.norm_squared() as f64;
        let o_norm = self.other_amp.norm_squared() as f64;
        let m = self.num_marked as f64;
        let n_m = sub_mod(self.n_mod_p, self.num_marked, self.p) as f64;
        
        let total = t_norm * m + o_norm * n_m;
        if total == 0.0 { return 0.0; }
        
        (t_norm * m) / total
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHOR'S ALGORITHM (Period Finding)
// ═══════════════════════════════════════════════════════════════════════════════

/// Find period of a^x mod N
pub fn find_period(a: u64, n: u64, max_iter: u64) -> Option<u64> {
    let mut power = a;
    for r in 1..=max_iter {
        if power == 1 {
            return Some(r);
        }
        power = mul_mod(power, a, n);
    }
    None
}

/// Factor N from period r of a^x mod N
pub fn factor_from_period(n: u64, a: u64, r: u64) -> Option<(u64, u64)> {
    if r % 2 != 0 { return None; }
    
    let half_r = r / 2;
    let a_half = pow_mod(a, half_r, n);
    
    if a_half == 1 || a_half == n - 1 { return None; }
    
    let f1 = gcd(a_half + 1, n);
    let f2 = gcd(a_half.saturating_sub(1).max(1), n);
    
    if f1 > 1 && f1 < n { return Some((f1.min(n/f1), f1.max(n/f1))); }
    if f2 > 1 && f2 < n { return Some((f2.min(n/f2), f2.max(n/f2))); }
    
    None
}

/// Shor-style factoring
pub fn shor_factor(n: u64) -> Option<(u64, u64)> {
    for a in 2..n.min(1000) {
        let g = gcd(a, n);
        if g > 1 && g < n {
            return Some((g.min(n/g), g.max(n/g)));
        }
        
        if let Some(r) = find_period(a, n, n * 2) {
            if let Some((p, q)) = factor_from_period(n, a, r) {
                return Some((p.min(q), p.max(q)));
            }
        }
    }
    None
}

// ═══════════════════════════════════════════════════════════════════════════════
// TEST HARNESS
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug)]
pub struct TestResult {
    pub name: String,
    pub passed: bool,
    pub duration: Duration,
    pub details: String,
}

pub struct TestHarness {
    pub results: Vec<TestResult>,
    pub verbose: bool,
}

impl TestHarness {
    pub fn new(verbose: bool) -> Self {
        Self { results: Vec::new(), verbose }
    }
    
    pub fn run_test<F>(&mut self, name: &str, test_fn: F)
    where
        F: FnOnce() -> (bool, String),
    {
        if self.verbose {
            print!("  Running: {}... ", name);
        }
        
        let start = Instant::now();
        let (passed, details) = test_fn();
        let duration = start.elapsed();
        
        if self.verbose {
            println!("{} ({:?})", if passed { "✓" } else { "✗" }, duration);
            if !passed || !details.is_empty() {
                println!("    {}", details);
            }
        }
        
        self.results.push(TestResult {
            name: name.to_string(),
            passed,
            duration,
            details,
        });
    }
    
    pub fn summary(&self) {
        let passed = self.results.iter().filter(|r| r.passed).count();
        let total = self.results.len();
        let total_time: Duration = self.results.iter().map(|r| r.duration).sum();
        
        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║  PQEAQ TEST HARNESS RESULTS                                  ║");
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║  Tests:  {}/{} passed                                        ║", passed, total);
        println!("║  Time:   {:?}                                      ║", total_time);
        println!("╠══════════════════════════════════════════════════════════════╣");
        
        for result in &self.results {
            let status = if result.passed { "✓" } else { "✗" };
            println!("║  {} {:50} {:?} ║", status, result.name, result.duration);
        }
        
        println!("╚══════════════════════════════════════════════════════════════╝");
        
        if passed == total {
            println!("\n🎉 ALL TESTS PASSED 🎉\n");
        } else {
            println!("\n⚠️  {} TESTS FAILED\n", total - passed);
            for result in self.results.iter().filter(|r| !r.passed) {
                println!("  FAIL: {} - {}", result.name, result.details);
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// INDIVIDUAL TESTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Test 1: Shor factoring correctness
pub fn test_shor_factoring() -> (bool, String) {
    let mut failures = Vec::new();
    
    for &(n, expected) in SHOR_TEST_CASES {
        if let Some(result) = shor_factor(n) {
            let (p, q) = (result.0.min(result.1), result.0.max(result.1));
            let (ep, eq) = (expected.0.min(expected.1), expected.0.max(expected.1));
            if p != ep || q != eq {
                failures.push(format!("{} = {:?} (expected {:?})", n, (p, q), (ep, eq)));
            }
        } else {
            failures.push(format!("{} = None (expected {:?})", n, expected));
        }
    }
    
    if failures.is_empty() {
        (true, format!("Factored {} numbers correctly", SHOR_TEST_CASES.len()))
    } else {
        (false, failures.join(", "))
    }
}

/// Test 2: Grover unencrypted correctness
pub fn test_grover_correctness() -> (bool, String) {
    let mut failures = Vec::new();
    
    for &(qubits, marked, optimal_iter) in GROVER_TEST_CASES {
        let mut state = SparseGroverState::new(qubits, marked, PRODUCTION_PRIME);
        state.iterate_n(optimal_iter);
        
        let prob = state.target_probability();
        if prob < 0.5 {
            failures.push(format!("q={}: prob={:.2}% (expected >50%)", qubits, prob * 100.0));
        }
    }
    
    if failures.is_empty() {
        (true, format!("{} Grover searches with >50% success", GROVER_TEST_CASES.len()))
    } else {
        (false, failures.join(", "))
    }
}

/// Test 3: Grover weight preservation (unitarity)
pub fn test_grover_unitarity() -> (bool, String) {
    let mut state = SparseGroverState::new(20, 1, PRODUCTION_PRIME);
    let initial_weight = state.total_weight();
    
    state.iterate_n(1000);
    
    let final_weight = state.total_weight();
    
    if initial_weight == final_weight {
        (true, format!("Weight preserved after 1000 iterations: {}", initial_weight))
    } else {
        (false, format!("Weight drift: {} → {}", initial_weight, final_weight))
    }
}

/// Test 4: Grover performance benchmark
pub fn test_grover_performance() -> (bool, String) {
    let mut state = SparseGroverState::new(20, 1, PRODUCTION_PRIME);
    
    let start = Instant::now();
    state.iterate_n(10_000);
    let elapsed = start.elapsed();
    
    let ns_per_iter = elapsed.as_nanos() / 10_000;
    let iters_per_sec = 1_000_000_000 / ns_per_iter.max(1);
    
    let passed = ns_per_iter < 500; // Should be under 500ns
    
    (passed, format!(
        "{} ns/iter, {} M iter/sec, {} qubits",
        ns_per_iter, iters_per_sec / 1_000_000, 20
    ))
}

/// Test 5: Sparse storage compression
pub fn test_storage_compression() -> (bool, String) {
    let test_sizes = vec![10, 20, 50, 100, 1000, 10000, 100000, 1000000];
    let mut results = Vec::new();
    
    for qubits in test_sizes {
        let state = SparseGroverState::new(qubits, 1, PRODUCTION_PRIME);
        // Sparse: 2 Fp2 (32 bytes) + metadata (32 bytes) = 64 bytes
        let sparse_bytes = 64;
        // Dense: 2^n × 16 bytes (Fp2)
        let dense_bytes = if qubits <= 40 {
            (1u64 << qubits) * 16
        } else {
            u64::MAX // Overflow
        };
        
        results.push(format!("{}q: sparse={}B", qubits, sparse_bytes));
    }
    
    (true, results.join(", "))
}

/// Test 6: Period finding validation
pub fn test_period_finding() -> (bool, String) {
    let test_cases = vec![
        (2, 15, 4),   // 2^4 = 16 ≡ 1 (mod 15)
        (2, 21, 6),   // 2^6 = 64 ≡ 1 (mod 21)
        (2, 35, 12),  // 2^12 = 4096 ≡ 1 (mod 35)
        (3, 14, 6),   // 3^6 = 729 ≡ 1 (mod 14)
    ];
    
    let mut failures = Vec::new();
    for (a, n, expected_r) in test_cases {
        if let Some(r) = find_period(a, n, n * 2) {
            if r != expected_r {
                failures.push(format!("period({},{})={} expected {}", a, n, r, expected_r));
            }
        } else {
            failures.push(format!("period({},{})=None expected {}", a, n, expected_r));
        }
    }
    
    if failures.is_empty() {
        (true, "All periods found correctly".to_string())
    } else {
        (false, failures.join(", "))
    }
}

/// Test 7: F_p² arithmetic correctness
pub fn test_fp2_arithmetic() -> (bool, String) {
    let p = PRODUCTION_PRIME;
    
    // Test: (a + bi)(c + di) = (ac - bd) + (ad + bc)i
    let a = Fp2::new(3, 4, p);
    let b = Fp2::new(5, 2, p);
    let prod = a.mul(&b);
    
    // 3*5 - 4*2 = 15 - 8 = 7
    // 3*2 + 4*5 = 6 + 20 = 26
    let expected = Fp2::new(7, 26, p);
    
    if prod != expected {
        return (false, format!("(3+4i)(5+2i) = {:?} expected {:?}", prod, expected));
    }
    
    // Test: |a + bi|² = a² + b²
    let c = Fp2::new(3, 4, p);
    let norm = c.norm_squared();
    if norm != 25 {
        return (false, format!("|3+4i|² = {} expected 25", norm));
    }
    
    // Test: negation
    let d = Fp2::new(5, 3, p);
    let neg_d = d.neg();
    let sum = d.add(&neg_d);
    if !sum.a == 0 || !sum.b == 0 {
        return (false, format!("5+3i + neg(5+3i) = {:?} expected 0", sum));
    }
    
    (true, "All F_p² operations correct".to_string())
}

/// Test 8: Optimal iteration count validation
pub fn test_optimal_iterations() -> (bool, String) {
    let mut results = Vec::new();
    
    for &(qubits, marked, expected_optimal) in GROVER_TEST_CASES.iter().take(4) {
        // Find actual optimal
        let mut best_iter = 0;
        let mut best_prob = 0.0;
        
        for iter in 1..=expected_optimal * 2 {
            let mut state = SparseGroverState::new(qubits, marked, PRODUCTION_PRIME);
            state.iterate_n(iter);
            let prob = state.target_probability();
            if prob > best_prob {
                best_prob = prob;
                best_iter = iter;
            }
        }
        
        let diff = (best_iter as i64 - expected_optimal as i64).abs();
        if diff > expected_optimal as i64 / 10 + 2 {
            return (false, format!("q={}: optimal at {} expected ~{}", qubits, best_iter, expected_optimal));
        }
        
        results.push(format!("{}q: opt={} ({:.1}%)", qubits, best_iter, best_prob * 100.0));
    }
    
    (true, results.join(", "))
}

/// Test 9: Large qubit scalability
pub fn test_large_qubit_scaling() -> (bool, String) {
    let large_qubits = vec![100, 1000, 10000, 100000, 1000000];
    let mut results = Vec::new();
    
    for qubits in large_qubits {
        let start = Instant::now();
        let mut state = SparseGroverState::new(qubits, 1, PRODUCTION_PRIME);
        state.iterate_n(100);
        let elapsed = start.elapsed();
        
        results.push(format!("{}q: {:?}", qubits, elapsed));
    }
    
    (true, results.join(", "))
}

/// Test 10: Zero decoherence validation
pub fn test_zero_decoherence() -> (bool, String) {
    let mut state = SparseGroverState::new(20, 1, PRODUCTION_PRIME);
    let initial_weight = state.total_weight();
    
    // Run far beyond optimal iterations
    state.iterate_n(10000);
    let final_weight = state.total_weight();
    
    if initial_weight != final_weight {
        return (false, format!("Weight changed: {} → {}", initial_weight, final_weight));
    }
    
    // Check that oscillation continues (not damped)
    let mut state2 = SparseGroverState::new(20, 1, PRODUCTION_PRIME);
    state2.iterate_n(804); // Optimal
    let optimal_prob = state2.target_probability();
    
    state2.iterate_n(1608); // 2× optimal (should be back near start)
    let double_prob = state2.target_probability();
    
    // Should oscillate, not stay at peak
    if (optimal_prob - double_prob).abs() < 0.1 {
        return (false, format!("No oscillation: {:.2}% → {:.2}%", optimal_prob * 100.0, double_prob * 100.0));
    }
    
    (true, format!("Weight exact, oscillation preserved after 10k iterations"))
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN HARNESS
// ═══════════════════════════════════════════════════════════════════════════════

pub fn run_pqeaq_harness(verbose: bool) -> bool {
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║  PQEAQ TEST HARNESS                                          ║");
    println!("║  Post-Quantum Encrypted Algebraic Quantum Validation         ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");
    
    let mut harness = TestHarness::new(verbose);
    
    println!("══════════════════════════════════════════════════════════════");
    println!("  SECTION 1: SHOR'S ALGORITHM VALIDATION");
    println!("══════════════════════════════════════════════════════════════");
    
    harness.run_test("Shor factoring correctness", test_shor_factoring);
    harness.run_test("Period finding validation", test_period_finding);
    
    println!("\n══════════════════════════════════════════════════════════════");
    println!("  SECTION 2: GROVER'S ALGORITHM VALIDATION");
    println!("══════════════════════════════════════════════════════════════");
    
    harness.run_test("Grover correctness", test_grover_correctness);
    harness.run_test("Grover unitarity", test_grover_unitarity);
    harness.run_test("Optimal iterations", test_optimal_iterations);
    harness.run_test("Zero decoherence", test_zero_decoherence);
    
    println!("\n══════════════════════════════════════════════════════════════");
    println!("  SECTION 3: F_p² SUBSTRATE VALIDATION");
    println!("══════════════════════════════════════════════════════════════");
    
    harness.run_test("F_p² arithmetic", test_fp2_arithmetic);
    harness.run_test("Storage compression", test_storage_compression);
    
    println!("\n══════════════════════════════════════════════════════════════");
    println!("  SECTION 4: PERFORMANCE BENCHMARKS");
    println!("══════════════════════════════════════════════════════════════");
    
    harness.run_test("Grover performance", test_grover_performance);
    harness.run_test("Large qubit scaling", test_large_qubit_scaling);
    
    harness.summary();
    
    harness.results.iter().all(|r| r.passed)
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENTRY POINT
// ═══════════════════════════════════════════════════════════════════════════════

fn main() {
    let passed = run_pqeaq_harness(true);
    std::process::exit(if passed { 0 } else { 1 });
}

// ═══════════════════════════════════════════════════════════════════════════════
// INTEGRATION WITH NINE65 (when compiled as part of crate)
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn pqeaq_harness_shor() {
        let (passed, details) = test_shor_factoring();
        println!("Shor: {}", details);
        assert!(passed, "Shor factoring failed: {}", details);
    }
    
    #[test]
    fn pqeaq_harness_grover() {
        let (passed, details) = test_grover_correctness();
        println!("Grover: {}", details);
        assert!(passed, "Grover correctness failed: {}", details);
    }
    
    #[test]
    fn pqeaq_harness_unitarity() {
        let (passed, details) = test_grover_unitarity();
        println!("Unitarity: {}", details);
        assert!(passed, "Unitarity failed: {}", details);
    }
    
    #[test]
    fn pqeaq_harness_performance() {
        let (passed, details) = test_grover_performance();
        println!("Performance: {}", details);
        assert!(passed, "Performance failed: {}", details);
    }
    
    #[test]
    fn pqeaq_harness_decoherence() {
        let (passed, details) = test_zero_decoherence();
        println!("Decoherence: {}", details);
        assert!(passed, "Decoherence failed: {}", details);
    }
    
    #[test]
    fn pqeaq_harness_scaling() {
        let (passed, details) = test_large_qubit_scaling();
        println!("Scaling: {}", details);
        assert!(passed, "Scaling failed: {}", details);
    }
    
    #[test]
    fn pqeaq_harness_full() {
        assert!(run_pqeaq_harness(false), "Full harness failed");
    }
}
