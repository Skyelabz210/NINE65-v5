//! State Compression Taxonomy - F1 Research Frontier
//!
//! Different quantum state families compress differently based on symmetry.
//! This module implements and characterizes:
//!
//! | State Family       | Symmetry Group | Storage    | Compression    |
//! |--------------------|----------------|------------|----------------|
//! | Uniform            | S_N            | O(1)       | 2^n : 1        |
//! | 1-marked Grover    | S_{N-1}        | O(1)       | 2^n : 1        |
//! | k-marked (struct)  | S_k × S_{N-k}  | O(1)       | 2^n : 1        |
//! | k-marked (random)  | Varies         | O(k)       | 2^n : k        |
//! | GHZ                | Z_2            | O(1)       | 2^n : 1        |
//! | Product            | Local          | O(n)       | 2^n : 2n       |
//! | Random             | Trivial        | O(2^n)     | 1 : 1          |
//!
//! All implementations use exact Fp2 arithmetic - zero drift.

use crate::ahop::Fp2Element;
use crate::params::mod_pow;

/// Compute 2^n mod p using repeated squaring
fn pow2_mod(n: usize, p: u64) -> u64 {
    if n == 0 { return 1; }
    let mut result = 1u64;
    let mut base = 2u64;
    let mut exp = n;
    while exp > 0 {
        if exp & 1 == 1 {
            result = ((result as u128 * base as u128) % p as u128) as u64;
        }
        base = ((base as u128 * base as u128) % p as u128) as u64;
        exp >>= 1;
    }
    result
}

// =============================================================================
// K-MARKED STATES (Structured)
// =============================================================================

/// Sparse k-marked state over Fp2 - O(1) storage when targets form equivalence class
///
/// When k targets are marked, we have 3 amplitude classes:
/// - Marked targets (k items, all same amplitude)
/// - Unmarked states (N-k items, all same amplitude)
///
/// Storage: 2 Fp2 elements + metadata = O(1)
#[derive(Clone, Debug)]
pub struct SparseKMarkedFp2 {
    /// Number of qubits
    pub num_qubits: usize,
    /// Number of marked targets
    pub k: usize,
    /// k mod p
    pub k_mod_p: u64,
    /// N mod p (2^n mod p)
    pub n_mod_p: u64,
    /// (N-k) mod p
    pub n_minus_k_mod_p: u64,
    /// N^(-1) mod p
    pub n_inv_mod_p: u64,
    /// Marked amplitude (all k targets share this)
    pub marked_amp: Fp2Element,
    /// Unmarked amplitude (all N-k others share this)
    pub unmarked_amp: Fp2Element,
    /// Prime modulus
    pub p: u64,
}

impl SparseKMarkedFp2 {
    /// Create uniform superposition with k marked targets
    pub fn uniform(num_qubits: usize, k: usize, p: u64) -> Self {
        assert!(p % 4 == 3, "Prime must be 3 mod 4 for Fp2");

        let n_mod_p = pow2_mod(num_qubits, p);
        let k_mod_p = (k as u64) % p;
        let n_minus_k_mod_p = (n_mod_p + p - k_mod_p) % p;
        let n_inv_mod_p = mod_pow(n_mod_p, p - 2, p);

        let initial_amp = Fp2Element::one(p);

        Self {
            num_qubits,
            k,
            k_mod_p,
            n_mod_p,
            n_minus_k_mod_p,
            n_inv_mod_p,
            marked_amp: initial_amp,
            unmarked_amp: initial_amp,
            p,
        }
    }

    /// Oracle: flip sign of all marked amplitudes
    #[inline]
    pub fn apply_oracle(&mut self) {
        self.marked_amp = self.marked_amp.neg();
    }

    /// Diffusion: 2|s⟩⟨s| - I over all states
    ///
    /// Mean = (k * marked_amp + (N-k) * unmarked_amp) / N
    pub fn apply_diffusion(&mut self) {
        // sum = k * marked + (N-k) * unmarked
        let marked_contrib = self.marked_amp.scalar_mul(self.k_mod_p);
        let unmarked_contrib = self.unmarked_amp.scalar_mul(self.n_minus_k_mod_p);
        let sum = marked_contrib.add(&unmarked_contrib);

        // mean = sum * N^(-1)
        let mean = sum.scalar_mul(self.n_inv_mod_p);

        // 2 * mean
        let two_mean = mean.add(&mean);

        // new amplitudes
        self.marked_amp = two_mean.sub(&self.marked_amp);
        self.unmarked_amp = two_mean.sub(&self.unmarked_amp);
    }

    /// Single Grover iteration
    #[inline]
    pub fn grover_iteration(&mut self) {
        self.apply_oracle();
        self.apply_diffusion();
    }

    /// Total Fp2 weight (should be preserved)
    pub fn total_weight(&self) -> u64 {
        let marked_sq = self.marked_amp.norm_squared();
        let unmarked_sq = self.unmarked_amp.norm_squared();

        let marked_contrib = ((marked_sq as u128 * self.k_mod_p as u128) % self.p as u128) as u64;
        let unmarked_contrib = ((unmarked_sq as u128 * self.n_minus_k_mod_p as u128) % self.p as u128) as u64;

        (marked_contrib + unmarked_contrib) % self.p
    }

    /// Approximate marked probability
    pub fn marked_probability(&self) -> f64 {
        let marked_weight = self.marked_amp.norm_squared() as f64 * self.k as f64;
        let unmarked_weight = self.unmarked_amp.norm_squared() as f64 * self.n_minus_k_mod_p as f64;
        let total = marked_weight + unmarked_weight;
        if total == 0.0 { return 0.0; }
        marked_weight / total
    }

    /// Storage in bytes (O(1))
    pub fn storage_bytes(&self) -> usize {
        // 2 Fp2 elements (16 bytes each) + metadata (~40 bytes)
        32 + 40
    }

    /// Compression ratio
    pub fn compression_ratio(&self) -> f64 {
        let full_storage = (1u128 << self.num_qubits.min(63)) as f64 * 16.0;
        full_storage / self.storage_bytes() as f64
    }
}

// =============================================================================
// GHZ STATE over Fp2
// =============================================================================

/// GHZ state over Fp2: |GHZ⟩ = α|00...0⟩ + β|11...1⟩
///
/// Only 2 nonzero amplitudes regardless of qubit count.
/// Storage: O(1)
#[derive(Clone, Debug)]
pub struct GHZStateFp2 {
    /// Number of qubits
    pub num_qubits: usize,
    /// Amplitude of |00...0⟩
    pub amp_zeros: Fp2Element,
    /// Amplitude of |11...1⟩
    pub amp_ones: Fp2Element,
    /// Prime modulus
    pub p: u64,
}

impl GHZStateFp2 {
    /// Create balanced GHZ: (|00...0⟩ + |11...1⟩)/√2
    /// We use integer weights, so amp_zeros = amp_ones = 1
    pub fn balanced(num_qubits: usize, p: u64) -> Self {
        assert!(p % 4 == 3, "Prime must be 3 mod 4 for Fp2");
        Self {
            num_qubits,
            amp_zeros: Fp2Element::one(p),
            amp_ones: Fp2Element::one(p),
            p,
        }
    }

    /// Create with custom amplitudes
    pub fn new(num_qubits: usize, amp_zeros: Fp2Element, amp_ones: Fp2Element) -> Self {
        let p = amp_zeros.p;
        assert_eq!(p, amp_ones.p, "Amplitudes must use same prime");
        Self { num_qubits, amp_zeros, amp_ones, p }
    }

    /// Total weight
    pub fn total_weight(&self) -> u64 {
        let w0 = self.amp_zeros.norm_squared();
        let w1 = self.amp_ones.norm_squared();
        (w0 + w1) % self.p
    }

    /// Probability of measuring all zeros
    pub fn prob_zeros(&self) -> f64 {
        let w0 = self.amp_zeros.norm_squared() as f64;
        let w1 = self.amp_ones.norm_squared() as f64;
        w0 / (w0 + w1)
    }

    /// Apply Hadamard to qubit i (transforms GHZ structure)
    /// H|0⟩ = |+⟩, H|1⟩ = |-⟩
    /// This can break the GHZ symmetry
    pub fn apply_hadamard(&mut self, _qubit: usize) {
        // H on any qubit transforms:
        // |00...0⟩ → |+0...0⟩ (superposition on first qubit)
        // |11...1⟩ → |-1...1⟩
        // This breaks 2-amplitude structure!
        // After H, we'd need more amplitudes.
        //
        // For now, we only support operations that preserve GHZ structure.
        unimplemented!("Hadamard breaks GHZ O(1) structure - use dense representation")
    }

    /// Apply global phase (preserves structure)
    pub fn apply_phase(&mut self, phase: Fp2Element) {
        self.amp_zeros = self.amp_zeros.mul(&phase);
        self.amp_ones = self.amp_ones.mul(&phase);
    }

    /// Apply Z gate to all qubits (|11...1⟩ gets phase flip)
    pub fn apply_global_z(&mut self) {
        self.amp_ones = self.amp_ones.neg();
    }

    /// Number of nonzero amplitudes
    pub fn nonzero_amplitudes(&self) -> usize {
        let mut count = 0;
        if self.amp_zeros.a != 0 || self.amp_zeros.b != 0 { count += 1; }
        if self.amp_ones.a != 0 || self.amp_ones.b != 0 { count += 1; }
        count
    }

    /// Storage in bytes
    pub fn storage_bytes(&self) -> usize {
        // 2 Fp2 elements + metadata
        32 + 16
    }
}

// =============================================================================
// PRODUCT STATE over Fp2
// =============================================================================

/// Product state: |ψ⟩ = |ψ₁⟩ ⊗ |ψ₂⟩ ⊗ ... ⊗ |ψₙ⟩
///
/// Each single-qubit state is (α|0⟩ + β|1⟩) = 2 Fp2 elements
/// Total storage: O(2n) = O(n)
#[derive(Clone, Debug)]
pub struct ProductStateFp2 {
    /// Single-qubit states: [(α₀, β₀), (α₁, β₁), ...]
    pub qubits: Vec<(Fp2Element, Fp2Element)>,
    /// Prime modulus
    pub p: u64,
}

impl ProductStateFp2 {
    /// Create |00...0⟩ product state
    pub fn all_zeros(num_qubits: usize, p: u64) -> Self {
        assert!(p % 4 == 3, "Prime must be 3 mod 4 for Fp2");
        let zero_state = (Fp2Element::one(p), Fp2Element::zero(p)); // |0⟩
        Self {
            qubits: vec![zero_state; num_qubits],
            p,
        }
    }

    /// Create |++...+⟩ product state (uniform superposition via Hadamard)
    pub fn all_plus(num_qubits: usize, p: u64) -> Self {
        assert!(p % 4 == 3, "Prime must be 3 mod 4 for Fp2");
        // |+⟩ = |0⟩ + |1⟩ (unnormalized, using integer weights)
        let plus_state = (Fp2Element::one(p), Fp2Element::one(p));
        Self {
            qubits: vec![plus_state; num_qubits],
            p,
        }
    }

    /// Number of qubits
    pub fn num_qubits(&self) -> usize {
        self.qubits.len()
    }

    /// Apply Hadamard to qubit i
    pub fn apply_hadamard(&mut self, i: usize) {
        let (alpha, beta) = &self.qubits[i];
        // H|ψ⟩ = H(α|0⟩ + β|1⟩) = α|+⟩ + β|-⟩ = (α+β)|0⟩ + (α-β)|1⟩
        let new_alpha = alpha.add(beta);
        let new_beta = alpha.sub(beta);
        self.qubits[i] = (new_alpha, new_beta);
    }

    /// Apply X gate to qubit i
    pub fn apply_x(&mut self, i: usize) {
        let (alpha, beta) = self.qubits[i].clone();
        self.qubits[i] = (beta, alpha);
    }

    /// Apply Z gate to qubit i
    pub fn apply_z(&mut self, i: usize) {
        let (alpha, beta) = &self.qubits[i];
        self.qubits[i] = (alpha.clone(), beta.neg());
    }

    /// Total weight (product of individual weights)
    pub fn total_weight(&self) -> u64 {
        let mut weight = 1u64;
        for (alpha, beta) in &self.qubits {
            let w = (alpha.norm_squared() + beta.norm_squared()) % self.p;
            weight = ((weight as u128 * w as u128) % self.p as u128) as u64;
        }
        weight
    }

    /// Probability of measuring qubit i as |0⟩
    pub fn prob_zero(&self, i: usize) -> f64 {
        let (alpha, beta) = &self.qubits[i];
        let w0 = alpha.norm_squared() as f64;
        let w1 = beta.norm_squared() as f64;
        w0 / (w0 + w1)
    }

    /// Storage in bytes: O(n)
    pub fn storage_bytes(&self) -> usize {
        // 2 Fp2 elements per qubit (32 bytes) + overhead
        self.qubits.len() * 32 + 16
    }

    /// Compression ratio vs full 2^n representation
    pub fn compression_ratio(&self) -> f64 {
        let n = self.num_qubits();
        if n > 63 { return f64::INFINITY; }
        let full = (1u64 << n) as f64 * 16.0;
        full / self.storage_bytes() as f64
    }
}

// =============================================================================
// TAXONOMY SUMMARY
// =============================================================================

/// State family classification
#[derive(Clone, Debug, PartialEq)]
pub enum StateFamily {
    Uniform,
    SingleMarkedGrover,
    KMarkedStructured(usize),
    GHZ,
    Product,
    Arbitrary,
}

/// Compression characteristics
#[derive(Clone, Debug)]
pub struct CompressionStats {
    pub family: StateFamily,
    pub num_qubits: usize,
    pub storage_bytes: usize,
    pub full_storage_bytes: u128,
    pub compression_ratio: f64,
    pub symmetry_group: String,
}

impl CompressionStats {
    pub fn for_k_marked(state: &SparseKMarkedFp2) -> Self {
        let full = if state.num_qubits < 64 {
            (1u128 << state.num_qubits) * 16
        } else {
            u128::MAX
        };
        Self {
            family: StateFamily::KMarkedStructured(state.k),
            num_qubits: state.num_qubits,
            storage_bytes: state.storage_bytes(),
            full_storage_bytes: full,
            compression_ratio: state.compression_ratio(),
            symmetry_group: format!("S_{} × S_{{N-{}}}", state.k, state.k),
        }
    }

    pub fn for_ghz(state: &GHZStateFp2) -> Self {
        let full = if state.num_qubits < 64 {
            (1u128 << state.num_qubits) * 16
        } else {
            u128::MAX
        };
        Self {
            family: StateFamily::GHZ,
            num_qubits: state.num_qubits,
            storage_bytes: state.storage_bytes(),
            full_storage_bytes: full,
            compression_ratio: full as f64 / state.storage_bytes() as f64,
            symmetry_group: "Z_2".to_string(),
        }
    }

    pub fn for_product(state: &ProductStateFp2) -> Self {
        let n = state.num_qubits();
        let full = if n < 64 {
            (1u128 << n) * 16
        } else {
            u128::MAX
        };
        Self {
            family: StateFamily::Product,
            num_qubits: n,
            storage_bytes: state.storage_bytes(),
            full_storage_bytes: full,
            compression_ratio: state.compression_ratio(),
            symmetry_group: "Local ⊗ structure".to_string(),
        }
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PRIME: u64 = 1_000_003;

    #[test]
    fn test_k_marked_weight_preservation() {
        println!("\n=== K-Marked Weight Preservation Test ===");

        for k in [1, 2, 5, 10, 100] {
            let mut state = SparseKMarkedFp2::uniform(50, k, TEST_PRIME);
            let initial_weight = state.total_weight();

            for _ in 0..1000 {
                state.grover_iteration();
            }

            let final_weight = state.total_weight();
            assert_eq!(initial_weight, final_weight,
                "Weight drift for k={}", k);

            println!("k={:3}: weight preserved ({} == {})", k, initial_weight, final_weight);
        }
    }

    #[test]
    fn test_k_marked_compression() {
        println!("\n=== K-Marked Compression Ratios ===");

        for n in [20, 50, 100, 1000] {
            let state = SparseKMarkedFp2::uniform(n, 10, TEST_PRIME);
            let stats = CompressionStats::for_k_marked(&state);

            println!("n={:4}: {} bytes, ratio={:.2e}, symmetry={}",
                n, stats.storage_bytes, stats.compression_ratio, stats.symmetry_group);
        }
    }

    #[test]
    fn test_ghz_state() {
        println!("\n=== GHZ State Test ===");

        for n in [10, 100, 1000, 10000] {
            let state = GHZStateFp2::balanced(n, TEST_PRIME);
            let stats = CompressionStats::for_ghz(&state);

            assert_eq!(state.nonzero_amplitudes(), 2);

            println!("n={:5}: {} amplitudes, {} bytes, ratio={:.2e}",
                n, state.nonzero_amplitudes(), stats.storage_bytes, stats.compression_ratio);
        }
    }

    #[test]
    fn test_ghz_weight_preservation() {
        let mut state = GHZStateFp2::balanced(100, TEST_PRIME);
        let initial = state.total_weight();

        // Apply operations that preserve GHZ structure
        for _ in 0..100 {
            state.apply_global_z();
            state.apply_phase(Fp2Element::one(TEST_PRIME));
        }

        assert_eq!(initial, state.total_weight());
        println!("GHZ weight preserved after 100 operations");
    }

    #[test]
    fn test_product_state() {
        println!("\n=== Product State Test ===");

        for n in [10, 100, 1000] {
            let state = ProductStateFp2::all_plus(n, TEST_PRIME);
            let stats = CompressionStats::for_product(&state);

            println!("n={:4}: {} bytes, ratio={:.2e}, O(n) confirmed",
                n, stats.storage_bytes, stats.compression_ratio);

            // Verify O(n) scaling
            assert!(stats.storage_bytes < n * 64, "Storage should be O(n)");
        }
    }

    #[test]
    fn test_product_hadamard() {
        let mut state = ProductStateFp2::all_zeros(5, TEST_PRIME);

        // Apply H to each qubit: |00000⟩ → |+++++⟩
        for i in 0..5 {
            state.apply_hadamard(i);
        }

        // Each qubit should now have equal probability
        for i in 0..5 {
            let p0 = state.prob_zero(i);
            assert!((p0 - 0.5).abs() < 0.01, "Qubit {} should be balanced", i);
        }

        println!("Product Hadamard test passed");
    }

    #[test]
    fn test_taxonomy_summary() {
        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║           STATE COMPRESSION TAXONOMY - F1 RESULTS            ║");
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║ Family          │ n=100 qubits │ Storage │ Compression       ║");
        println!("╠══════════════════════════════════════════════════════════════╣");

        // 1-marked Grover
        let grover1 = SparseKMarkedFp2::uniform(100, 1, TEST_PRIME);
        println!("║ 1-marked Grover │ 2^100 states │ {:4} B  │ {:.2e}:1      ║",
            grover1.storage_bytes(), grover1.compression_ratio());

        // k-marked (k=10)
        let groverk = SparseKMarkedFp2::uniform(100, 10, TEST_PRIME);
        println!("║ 10-marked       │ 2^100 states │ {:4} B  │ {:.2e}:1      ║",
            groverk.storage_bytes(), groverk.compression_ratio());

        // GHZ
        let ghz = GHZStateFp2::balanced(100, TEST_PRIME);
        let ghz_stats = CompressionStats::for_ghz(&ghz);
        println!("║ GHZ             │ 2^100 states │ {:4} B  │ {:.2e}:1      ║",
            ghz_stats.storage_bytes, ghz_stats.compression_ratio);

        // Product
        let product = ProductStateFp2::all_plus(100, TEST_PRIME);
        let prod_stats = CompressionStats::for_product(&product);
        println!("║ Product         │ 2^100 states │ {:4} B │ {:.2e}:1      ║",
            prod_stats.storage_bytes, prod_stats.compression_ratio);

        println!("╚══════════════════════════════════════════════════════════════╝");
    }
}
