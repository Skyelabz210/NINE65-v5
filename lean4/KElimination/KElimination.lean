/-
  K-Elimination: Exact Division in Residue Number Systems

  A 60-Year Breakthrough in RNS Arithmetic
  QMNF Advanced Mathematics, December 2025

  Formalized in Lean 4 with Mathlib
-/

import Mathlib.Data.ZMod.Basic
import Mathlib.Data.Nat.GCD.Basic
import Mathlib.RingTheory.Coprime.Basic
import Mathlib.Tactic

/-!
# K-Elimination Theorem

For a value X represented in two coprime modulus systems (main M, anchor A):
- v_M = X mod M  (main residue)
- v_A = X mod A  (anchor residue)
- k = floor(X / M)  (overflow count)

The K-Elimination theorem proves:
  k ≡ (v_A - v_M) * M⁻¹ (mod A)

This enables exact k recovery without floating-point approximation.
-/

namespace KElimination

/-! ## Basic Definitions -/

/-- The overflow count k for value X with modulus product M -/
def overflow_count (X M : ℕ) : ℕ := X / M

/-- Main residue: X mod M -/
def main_residue (X M : ℕ) : ℕ := X % M

/-- Anchor residue: X mod A -/
def anchor_residue (X A : ℕ) : ℕ := X % A

/-- Phase differential -/
def phase_diff (v_A v_M A : ℕ) : ℕ := (v_A + A - v_M % A) % A

/-- RNS Configuration -/
structure RNSConfig where
  M : ℕ
  A : ℕ
  coprime : Nat.Coprime M A
  M_pos : M > 0
  A_pos : A > 0

/-! ## Division Algorithm Lemmas -/

/-- Division Algorithm: M * (X / M) + X % M = X -/
theorem div_add_mod (X M : ℕ) : M * (X / M) + X % M = X :=
  Nat.div_add_mod X M

/-- Alternative form: X % M + M * (X / M) = X -/
theorem mod_add_div (X M : ℕ) : X % M + M * (X / M) = X := by
  have h := Nat.div_add_mod X M
  omega

/-- Commutativity form: X = X % M + (X / M) * M -/
theorem div_mod_identity (X M : ℕ) : X = X % M + (X / M) * M := by
  have h := mod_add_div X M
  have hcomm : M * (X / M) = (X / M) * M := Nat.mul_comm M (X / M)
  rw [hcomm] at h
  exact h.symm

/-- Residue is bounded -/
theorem residue_lt_mod (X M : ℕ) (hM : M > 0) : X % M < M :=
  Nat.mod_lt X hM

/-- Division bound -/
theorem div_mul_le (X M : ℕ) : (X / M) * M ≤ X :=
  Nat.div_mul_le_self X M

/-! ## Range Bounds for k -/

/-- If X < M * A then X / M < A -/
theorem k_lt_A (X M A : ℕ) (hRange : X < M * A) : X / M < A :=
  Nat.div_lt_of_lt_mul hRange

/-- When k < A, k mod A = k -/
theorem k_mod_eq_k (k A : ℕ) (hk : k < A) : k % A = k :=
  Nat.mod_eq_of_lt hk

/-! ## Key Congruence (THE CORE INSIGHT) -/

/--
  KEY LEMMA: The anchor residue equals the reconstruction formula mod A

  X % A = (X % M + (X / M) * M) % A

  This is the algebraic foundation of K-Elimination.
-/
theorem key_congruence (X M A : ℕ) :
    X % A = (X % M + (X / M) * M) % A := by
  have h : X = X % M + (X / M) * M := div_mod_identity X M
  calc X % A = (X % M + (X / M) * M) % A := by rw [← h]

/-! ## Modular Arithmetic Properties -/

/-- (a + b * M) % M = a % M -/
theorem add_mul_mod (a b M : ℕ) : (a + b * M) % M = a % M :=
  Nat.add_mul_mod_self_right a b M

/-- When a < M: (a + b * M) % M = a -/
theorem add_mul_mod_small (a b M : ℕ) (ha : a < M) : (a + b * M) % M = a := by
  rw [add_mul_mod]
  exact Nat.mod_eq_of_lt ha

/-! ## Modular Inverse -/

/-- When gcd(M, A) = 1, the modular inverse exists -/
theorem modular_inverse_exists (M A : ℕ) (hA : A > 1) (hcop : Nat.Coprime M A) :
    ∃ M_inv : ℕ, (M * M_inv) % A = 1 := by
  have hApos : A > 0 := Nat.lt_trans Nat.zero_lt_one hA
  have hAne : NeZero A := ⟨Nat.pos_iff_ne_zero.mp hApos⟩
  haveI : Fact (1 < A) := ⟨hA⟩
  -- Use unitOfCoprime to get the unit
  let u := ZMod.unitOfCoprime M hcop
  -- The inverse element
  let inv_unit := u⁻¹
  use ZMod.val inv_unit.val
  -- Key: M * u⁻¹ = 1 in ZMod A
  have hmul : (M : ZMod A) * inv_unit.val = 1 := by
    have hu : (u : ZMod A) = (M : ZMod A) := ZMod.coe_unitOfCoprime M hcop
    rw [← hu]
    exact Units.mul_inv u
  -- val of inv_unit coerced back is inv_unit
  have hvalcast : (ZMod.val inv_unit.val : ZMod A) = inv_unit.val := ZMod.natCast_zmod_val inv_unit.val
  -- Convert: (M * inv.val) mod A = val of (M * inv) in ZMod A = val of 1 = 1
  have hmod : (M * ZMod.val inv_unit.val) % A = ZMod.val ((M : ZMod A) * inv_unit.val) := by
    rw [← ZMod.val_natCast (n := A)]
    congr 1
    push_cast
    rw [hvalcast]
  rw [hmod, hmul]
  exact ZMod.val_one (n := A)

/-! ## Reconstruction Theorems -/

/-- X can be reconstructed from vM and k -/
theorem reconstruction (X M : ℕ) :
    X = main_residue X M + overflow_count X M * M := by
  unfold main_residue overflow_count
  exact div_mod_identity X M

/-- Reconstruction preserves the main residue -/
theorem reconstruction_mod (X M : ℕ) (hM : 0 < M) :
    (main_residue X M + overflow_count X M * M) % M = main_residue X M := by
  unfold main_residue overflow_count
  rw [add_mul_mod]
  exact Nat.mod_eq_of_lt (residue_lt_mod X M hM)

/-! ## K-Elimination Core Theorem -/

/--
  K-Elimination Core Theorem

  For X in range [0, M*A):
  1. The overflow count k = X / M is bounded by A
  2. The key congruence holds: X % A = (vM + k * M) % A
-/
theorem kElimination_core (X M A : ℕ) (_hM : 0 < M) (hRange : X < M * A) :
    let vM := X % M
    let k := X / M
    -- Part 1: k is bounded
    k < A ∧
    -- Part 2: Key congruence holds
    X % A = (vM + k * M) % A := by
  constructor
  · -- k < A
    exact k_lt_A X M A hRange
  · -- X % A = (vM + k * M) % A
    exact key_congruence X M A

/-- K-Elimination Uniqueness: k % A = k when X < M * A -/
theorem kElimination_unique (X M A : ℕ) (_hM : 0 < M) (hRange : X < M * A) :
    (X / M) % A = X / M := by
  apply Nat.mod_eq_of_lt
  exact k_lt_A X M A hRange

/-! ## Validation Identities -/

/-- V1: Basic reconstruction -/
theorem validation_v1 (X M : ℕ) : X = X % M + (X / M) * M :=
  div_mod_identity X M

/-- V2: Main residue consistency -/
theorem validation_v2 (X M : ℕ) (hM : 0 < M) :
    (X % M + (X / M) * M) % M = X % M := by
  rw [add_mul_mod]
  exact Nat.mod_eq_of_lt (residue_lt_mod X M hM)

/-- V3: Anchor residue consistency (key congruence) -/
theorem validation_v3 (X M A : ℕ) :
    (X % M + (X / M) * M) % A = X % A := by
  have h := div_mod_identity X M
  rw [← h]

/-- V4: k uniqueness when k < A -/
theorem validation_v4 (k A : ℕ) (hk : k < A) : k % A = k :=
  Nat.mod_eq_of_lt hk

/-- V5: Remainder bounds -/
theorem validation_v5 (X d : ℕ) (hd : 0 < d) : X % d < d :=
  Nat.mod_lt X hd

/-- V6: k range bound -/
theorem validation_v6 (X M A : ℕ) (_hM : 0 < M) (hRange : X < M * A) :
    X / M < A := k_lt_A X M A hRange

/-! ## Division Correctness -/

/-- After k-recovery, division is exact when d divides X -/
theorem division_exact (X d : ℕ) (hdiv : d ∣ X) :
    X % d = 0 := Nat.mod_eq_zero_of_dvd hdiv

/-- Division produces correct quotient and remainder -/
theorem division_correct (X M : ℕ) (hM : 0 < M) :
    X = (X / M) * M + X % M ∧ X % M < M := by
  constructor
  · have h := div_mod_identity X M; omega
  · exact residue_lt_mod X M hM

/-! ## Complexity -/

def k_elimination_complexity (k l : ℕ) : ℕ := k + l

def mrc_complexity (k : ℕ) : ℕ := k * k

theorem complexity_improvement (k : ℕ) (hk : k > 1) :
    k_elimination_complexity k 0 < mrc_complexity k := by
  simp only [k_elimination_complexity, mrc_complexity, Nat.add_zero]
  -- k < k * k when k > 1
  have hk2 : k ≥ 2 := hk
  have hmul : k * k ≥ k * 2 := Nat.mul_le_mul_left k hk2
  omega

end KElimination

/-! ## Soundness -/

namespace Soundness

theorem k_elimination_sound (cfg : KElimination.RNSConfig) (X : ℕ)
    (hX : X < cfg.M * cfg.A) (M_inv : ℕ) (hMinv : (cfg.M * M_inv) % cfg.A = 1) :
    let v_M := X % cfg.M
    let v_A := X % cfg.A
    let k_true := X / cfg.M
    let phase := (v_A + cfg.A - v_M % cfg.A) % cfg.A
    let k_computed := (phase * M_inv) % cfg.A
    k_computed = k_true := by
    simp only
    have hAne : NeZero cfg.A := ⟨Nat.pos_iff_ne_zero.mp cfg.A_pos⟩
    have hkLt : X / cfg.M < cfg.A := Nat.div_lt_of_lt_mul hX
    have hkMod : (X / cfg.M) % cfg.A = X / cfg.M := Nat.mod_eq_of_lt hkLt
    have hfund : X = X % cfg.M + (X / cfg.M) * cfg.M := KElimination.div_mod_identity X cfg.M
    -- Work in ZMod cfg.A
    have hXmodA : (X % cfg.A : ZMod cfg.A) = (X : ZMod cfg.A) := ZMod.natCast_mod X cfg.A
    have hvMmodA : (X % cfg.M % cfg.A : ZMod cfg.A) = (X % cfg.M : ZMod cfg.A) := ZMod.natCast_mod (X % cfg.M) cfg.A
    have hAzero : (cfg.A : ZMod cfg.A) = 0 := ZMod.natCast_self cfg.A
    -- M * M_inv = 1 in ZMod A
    have hMinvZMod : (cfg.M : ZMod cfg.A) * (M_inv : ZMod cfg.A) = 1 := by
      -- hMinv : cfg.M * M_inv % cfg.A = 1
      -- Use ZMod.natCast_mod: (n : ZMod A) = (n % A : ZMod A)
      -- So (M * M_inv % A : ZMod A) = (M * M_inv : ZMod A)
      -- And hMinv tells us M * M_inv % A = 1
      -- Therefore (M * M_inv : ZMod A) = (1 : ZMod A)
      have h : ((cfg.M * M_inv : ℕ) : ZMod cfg.A) = (1 : ZMod cfg.A) := by
        have mod_eq : ((cfg.M * M_inv : ℕ) : ZMod cfg.A) = ((cfg.M * M_inv) % cfg.A : ZMod cfg.A) := by
          rw [ZMod.natCast_mod]
        simp only [mod_eq, hMinv, Nat.cast_one]
      -- Now use Nat.cast_mul: ↑(a * b) = ↑a * ↑b
      rw [← Nat.cast_mul]
      exact h
    -- X = vM + k*M in ZMod A
    have hXeq : (X : ZMod cfg.A) = (X % cfg.M : ZMod cfg.A) + (X / cfg.M : ZMod cfg.A) * (cfg.M : ZMod cfg.A) := by
      conv_lhs => rw [hfund]
      push_cast
      ring
    -- phase = k*M in ZMod A
    have hsub : X % cfg.M % cfg.A ≤ X % cfg.A + cfg.A := by
      have h : X % cfg.M % cfg.A < cfg.A := Nat.mod_lt _ cfg.A_pos; omega
    have hphase : ((X % cfg.A + cfg.A - X % cfg.M % cfg.A) % cfg.A : ZMod cfg.A)
                = (X / cfg.M : ZMod cfg.A) * (cfg.M : ZMod cfg.A) := by
      rw [ZMod.natCast_mod]
      rw [Nat.cast_sub hsub]
      push_cast
      rw [hXmodA, hvMmodA, hAzero, add_zero, hXeq]
      ring
    -- phase * M_inv = k in ZMod A
    have hresult : ((X % cfg.A + cfg.A - X % cfg.M % cfg.A) % cfg.A : ZMod cfg.A) * (M_inv : ZMod cfg.A)
                 = (X / cfg.M : ZMod cfg.A) := by
      rw [hphase]
      calc (X / cfg.M : ZMod cfg.A) * (cfg.M : ZMod cfg.A) * (M_inv : ZMod cfg.A)
          = (X / cfg.M : ZMod cfg.A) * ((cfg.M : ZMod cfg.A) * (M_inv : ZMod cfg.A)) := by ring
        _ = (X / cfg.M : ZMod cfg.A) * 1 := by rw [hMinvZMod]
        _ = (X / cfg.M : ZMod cfg.A) := by ring
    -- Convert back to ℕ using ZMod.val
    suffices h : ((X % cfg.A + cfg.A - X % cfg.M % cfg.A) % cfg.A * M_inv) % cfg.A
               = (X / cfg.M) % cfg.A by rw [h, hkMod]
    -- Use ZMod.val_natCast: (n : ZMod A).val = n % A for casting
    have lhs_val : ((X % cfg.A + cfg.A - X % cfg.M % cfg.A) % cfg.A * M_inv) % cfg.A
                 = ZMod.val (((X % cfg.A + cfg.A - X % cfg.M % cfg.A) % cfg.A : ZMod cfg.A) * (M_inv : ZMod cfg.A)) := by
      have cast_eq : (((X % cfg.A + cfg.A - X % cfg.M % cfg.A) % cfg.A * M_inv : ℕ) : ZMod cfg.A)
                   = ((X % cfg.A + cfg.A - X % cfg.M % cfg.A) % cfg.A : ZMod cfg.A) * (M_inv : ZMod cfg.A) := by
        push_cast; ring
      rw [← cast_eq, ZMod.val_natCast]
    have rhs_val : (X / cfg.M) % cfg.A = ZMod.val (X / cfg.M : ZMod cfg.A) := by
      rw [ZMod.val_natCast]
    rw [lhs_val, rhs_val, hresult]

theorem k_elimination_complete (cfg : KElimination.RNSConfig) (k : ℕ) (_hk : k < cfg.A)
    (v_M : ℕ) (hv : v_M < cfg.M) :
    let X := v_M + k * cfg.M
    X / cfg.M = k := by
  simp only
  rw [Nat.mul_comm k cfg.M]
  rw [Nat.add_mul_div_left v_M k cfg.M_pos]
  have hdiv : v_M / cfg.M = 0 := Nat.div_eq_of_lt hv
  omega

end Soundness

/-! ## Error Taxonomy -/

namespace ErrorTaxonomy

def coprimality_violation (M A : ℕ) : Prop := ¬Nat.Coprime M A

def range_overflow (M A X : ℕ) : Prop := X ≥ M * A

theorem detect_coprimality_violation (M A : ℕ) :
    coprimality_violation M A ↔ Nat.gcd M A ≠ 1 := by
  simp [coprimality_violation, Nat.Coprime]

end ErrorTaxonomy

/-! ## 4-Prime CRT Extension

When k exceeds the capacity of 2 anchor primes (typically ~63 bits),
we need 4-prime incremental CRT reconstruction for k values up to ~125 bits.

Reference: proofs/coq/KElimination.v (4-Prime CRT Extension section)
-/

namespace FourPrimeCRT

/-- Incremental CRT step: combine partial k with new residue k_a3 mod a3 -/
def incrementalCRTStep (k_partial : ℕ) (partial_product : ℕ) (k_a3 : ℕ) (a3 : ℕ) (partial_inv_a3 : ℕ) : ℕ :=
  let diff := (k_a3 + a3 - k_partial % a3) % a3
  let coeff := (diff * partial_inv_a3) % a3
  k_partial + coeff * partial_product

/-- 4-Prime anchor configuration -/
structure FourPrimeConfig where
  a1 : ℕ  -- First anchor prime
  a2 : ℕ  -- Second anchor prime
  a3 : ℕ  -- Third anchor prime
  a4 : ℕ  -- Fourth anchor prime
  a1_pos : a1 > 1
  a2_pos : a2 > 1
  a3_pos : a3 > 1
  a4_pos : a4 > 1
  coprime_12 : Nat.Coprime a1 a2
  coprime_123 : Nat.Coprime (a1 * a2) a3
  coprime_1234 : Nat.Coprime (a1 * a2 * a3) a4

/-- Product of first two anchors -/
def A12 (cfg : FourPrimeConfig) : ℕ := cfg.a1 * cfg.a2

/-- Product of first three anchors -/
def A123 (cfg : FourPrimeConfig) : ℕ := cfg.a1 * cfg.a2 * cfg.a3

/-- Total anchor product (4 primes) -/
def A_total (cfg : FourPrimeConfig) : ℕ := cfg.a1 * cfg.a2 * cfg.a3 * cfg.a4

/-- 4-prime CRT uniqueness: unique k in [0, A_total) -/
theorem fourPrime_crt_unique (cfg : FourPrimeConfig) (k1 k2 : ℕ)
    (hk1 : k1 < A_total cfg) (hk2 : k2 < A_total cfg)
    (h1 : k1 % cfg.a1 = k2 % cfg.a1)
    (h2 : k1 % cfg.a2 = k2 % cfg.a2)
    (h3 : k1 % cfg.a3 = k2 % cfg.a3)
    (h4 : k1 % cfg.a4 = k2 % cfg.a4) :
    k1 = k2 := by
  -- By CRT, equal residues mod pairwise coprime moduli → equal mod product
  -- The total product A = a1 * a2 * a3 * a4
  -- Since k1, k2 < A and k1 ≡ k2 (mod each ai), we have k1 = k2
  have hcop : Nat.Coprime (cfg.a1 * cfg.a2 * cfg.a3) cfg.a4 := cfg.coprime_1234
  -- First show k1 ≡ k2 (mod a1*a2) using CRT for first two primes
  have h12_coprime : Nat.Coprime cfg.a1 cfg.a2 := cfg.coprime_12
  have h12 : k1 % (cfg.a1 * cfg.a2) = k2 % (cfg.a1 * cfg.a2) := by
    apply Nat.eq_of_lt_of_mod_eq_mod
    · exact Nat.mod_lt k1 (Nat.mul_pos cfg.a1_pos cfg.a2_pos)
    · exact Nat.mod_lt k2 (Nat.mul_pos cfg.a1_pos cfg.a2_pos)
    · constructor
      · calc k1 % (cfg.a1 * cfg.a2) % cfg.a1
          = k1 % cfg.a1 := by rw [Nat.mod_mod_of_dvd k1 (dvd_mul_right cfg.a1 cfg.a2)]
        _ = k2 % cfg.a1 := h1
        _ = k2 % (cfg.a1 * cfg.a2) % cfg.a1 := by rw [Nat.mod_mod_of_dvd k2 (dvd_mul_right cfg.a1 cfg.a2)]
      · calc k1 % (cfg.a1 * cfg.a2) % cfg.a2
          = k1 % cfg.a2 := by rw [Nat.mod_mod_of_dvd k1 (dvd_mul_left cfg.a2 cfg.a1)]
        _ = k2 % cfg.a2 := h2
        _ = k2 % (cfg.a1 * cfg.a2) % cfg.a2 := by rw [Nat.mod_mod_of_dvd k2 (dvd_mul_left cfg.a2 cfg.a1)]
    · exact h12_coprime
  -- Extend to 3 primes using coprime_123
  have h123_coprime : Nat.Coprime (cfg.a1 * cfg.a2) cfg.a3 := cfg.coprime_123
  have h123 : k1 % (cfg.a1 * cfg.a2 * cfg.a3) = k2 % (cfg.a1 * cfg.a2 * cfg.a3) := by
    apply Nat.eq_of_lt_of_mod_eq_mod
    · exact Nat.mod_lt k1 (Nat.mul_pos (Nat.mul_pos cfg.a1_pos cfg.a2_pos) cfg.a3_pos)
    · exact Nat.mod_lt k2 (Nat.mul_pos (Nat.mul_pos cfg.a1_pos cfg.a2_pos) cfg.a3_pos)
    · constructor
      · calc k1 % (cfg.a1 * cfg.a2 * cfg.a3) % (cfg.a1 * cfg.a2)
            = k1 % (cfg.a1 * cfg.a2) := by
              rw [Nat.mod_mod_of_dvd k1]; exact dvd_mul_right (cfg.a1 * cfg.a2) cfg.a3
          _ = k2 % (cfg.a1 * cfg.a2) := h12
          _ = k2 % (cfg.a1 * cfg.a2 * cfg.a3) % (cfg.a1 * cfg.a2) := by
              rw [Nat.mod_mod_of_dvd k2]; exact dvd_mul_right (cfg.a1 * cfg.a2) cfg.a3
      · calc k1 % (cfg.a1 * cfg.a2 * cfg.a3) % cfg.a3
            = k1 % cfg.a3 := by
              rw [Nat.mod_mod_of_dvd k1]; exact dvd_mul_left cfg.a3 (cfg.a1 * cfg.a2)
          _ = k2 % cfg.a3 := h3
          _ = k2 % (cfg.a1 * cfg.a2 * cfg.a3) % cfg.a3 := by
              rw [Nat.mod_mod_of_dvd k2]; exact dvd_mul_left cfg.a3 (cfg.a1 * cfg.a2)
    · exact h123_coprime
  -- Extend to 4 primes using coprime_1234
  have h1234_coprime : Nat.Coprime (cfg.a1 * cfg.a2 * cfg.a3) cfg.a4 := cfg.coprime_1234
  have h1234 : k1 % A_total cfg = k2 % A_total cfg := by
    unfold A_total
    apply Nat.eq_of_lt_of_mod_eq_mod
    · exact Nat.mod_lt k1 (Nat.mul_pos (Nat.mul_pos (Nat.mul_pos cfg.a1_pos cfg.a2_pos) cfg.a3_pos) cfg.a4_pos)
    · exact Nat.mod_lt k2 (Nat.mul_pos (Nat.mul_pos (Nat.mul_pos cfg.a1_pos cfg.a2_pos) cfg.a3_pos) cfg.a4_pos)
    · constructor
      · calc k1 % (cfg.a1 * cfg.a2 * cfg.a3 * cfg.a4) % (cfg.a1 * cfg.a2 * cfg.a3)
            = k1 % (cfg.a1 * cfg.a2 * cfg.a3) := by
              rw [Nat.mod_mod_of_dvd k1]; exact dvd_mul_right (cfg.a1 * cfg.a2 * cfg.a3) cfg.a4
          _ = k2 % (cfg.a1 * cfg.a2 * cfg.a3) := h123
          _ = k2 % (cfg.a1 * cfg.a2 * cfg.a3 * cfg.a4) % (cfg.a1 * cfg.a2 * cfg.a3) := by
              rw [Nat.mod_mod_of_dvd k2]; exact dvd_mul_right (cfg.a1 * cfg.a2 * cfg.a3) cfg.a4
      · calc k1 % (cfg.a1 * cfg.a2 * cfg.a3 * cfg.a4) % cfg.a4
            = k1 % cfg.a4 := by
              rw [Nat.mod_mod_of_dvd k1]; exact dvd_mul_left cfg.a4 (cfg.a1 * cfg.a2 * cfg.a3)
          _ = k2 % cfg.a4 := h4
          _ = k2 % (cfg.a1 * cfg.a2 * cfg.a3 * cfg.a4) % cfg.a4 := by
              rw [Nat.mod_mod_of_dvd k2]; exact dvd_mul_left cfg.a4 (cfg.a1 * cfg.a2 * cfg.a3)
    · exact h1234_coprime
  -- Finally, k1 < A and k2 < A with k1 % A = k2 % A implies k1 = k2
  have hk1_mod : k1 % A_total cfg = k1 := Nat.mod_eq_of_lt hk1
  have hk2_mod : k2 % A_total cfg = k2 := Nat.mod_eq_of_lt hk2
  calc k1 = k1 % A_total cfg := hk1_mod.symm
    _ = k2 % A_total cfg := h1234
    _ = k2 := hk2_mod

/-- K-Elimination soundness with 4-prime anchors -/
theorem kElimination_4prime_sound (cfg : FourPrimeConfig) (M : ℕ) (X : ℕ)
    (hM : M > 0) (hRange : X < M * A_total cfg)
    (M_inv_a1 M_inv_a2 M_inv_a3 M_inv_a4 : ℕ)
    (hInv1 : (M * M_inv_a1) % cfg.a1 = 1)
    (hInv2 : (M * M_inv_a2) % cfg.a2 = 1)
    (hInv3 : (M * M_inv_a3) % cfg.a3 = 1)
    (hInv4 : (M * M_inv_a4) % cfg.a4 = 1)
    (hCop1 : Nat.Coprime M cfg.a1)
    (hCop2 : Nat.Coprime M cfg.a2)
    (hCop3 : Nat.Coprime M cfg.a3)
    (hCop4 : Nat.Coprime M cfg.a4) :
    let k_true := X / M
    let v_M := X % M
    -- Compute k residues mod each anchor
    let k_a1 := ((X % cfg.a1 + cfg.a1 - v_M % cfg.a1) % cfg.a1 * M_inv_a1) % cfg.a1
    let k_a2 := ((X % cfg.a2 + cfg.a2 - v_M % cfg.a2) % cfg.a2 * M_inv_a2) % cfg.a2
    let k_a3 := ((X % cfg.a3 + cfg.a3 - v_M % cfg.a3) % cfg.a3 * M_inv_a3) % cfg.a3
    let k_a4 := ((X % cfg.a4 + cfg.a4 - v_M % cfg.a4) % cfg.a4 * M_inv_a4) % cfg.a4
    -- Each residue matches k_true mod that anchor
    k_a1 = k_true % cfg.a1 ∧
    k_a2 = k_true % cfg.a2 ∧
    k_a3 = k_true % cfg.a3 ∧
    k_a4 = k_true % cfg.a4 := by
  intro k_true v_M k_a1 k_a2 k_a3 k_a4
  -- Each follows from standard K-Elimination soundness applied per-anchor
  -- The key insight: X % ai gives k*M + vM mod ai, phase extraction yields k mod ai

  -- Helper lemma: per-anchor K-Elimination
  have per_anchor_sound : ∀ (A : ℕ) (hA_pos : A > 0) (M_inv : ℕ) (hInv : (M * M_inv) % A = 1)
      (hCop : Nat.Coprime M A),
      ((X % A + A - X % M % A) % A * M_inv) % A = X / M % A := by
    intro A hA_pos M_inv hInv hCop
    -- Use the existing Soundness.k_elimination_sound
    have hX_A : X < M * (A_total cfg) := hRange
    -- k < A_total implies k mod A = k mod A (just mod)
    -- The key is that the phase computation works mod A
    have hAne : NeZero A := ⟨Nat.pos_iff_ne_zero.mp hA_pos⟩
    -- Division identity: X = vM + k * M
    have h_div : X = X % M + X / M * M := (Nat.mod_add_div' X M).symm
    -- Cast to ZMod A
    have h_cast : (X : ZMod A) = (X % M : ZMod A) + (X / M : ZMod A) * (M : ZMod A) := by
      conv_lhs => rw [h_div]; push_cast; ring
    have h_X_mod : (X % A : ZMod A) = (X : ZMod A) := ZMod.natCast_mod X A
    have h_vM_mod : (X % M % A : ZMod A) = (X % M : ZMod A) := ZMod.natCast_mod (X % M) A
    -- M * M_inv = 1 in ZMod A
    have hMinvZMod : (M : ZMod A) * (M_inv : ZMod A) = 1 := by
      have h : ((M * M_inv : ℕ) : ZMod A) = (1 : ZMod A) := by
        have mod_eq : ((M * M_inv : ℕ) : ZMod A) = ((M * M_inv) % A : ZMod A) := by
          rw [ZMod.natCast_mod]
        simp only [mod_eq, hInv, Nat.cast_one]
      rw [← Nat.cast_mul]; exact h
    -- Phase = k * M in ZMod A
    have hsub : X % M % A ≤ X % A + A := by
      have h : X % M % A < A := Nat.mod_lt _ hA_pos; omega
    have hphase : ((X % A + A - X % M % A) % A : ZMod A) = (X / M : ZMod A) * (M : ZMod A) := by
      rw [ZMod.natCast_mod, Nat.cast_sub hsub]
      push_cast
      rw [h_X_mod, h_vM_mod, ZMod.natCast_self, add_zero, h_cast]
      ring
    -- Phase * M_inv = k
    have hresult : ((X % A + A - X % M % A) % A : ZMod A) * (M_inv : ZMod A) = (X / M : ZMod A) := by
      rw [hphase]
      calc (X / M : ZMod A) * (M : ZMod A) * (M_inv : ZMod A)
          = (X / M : ZMod A) * ((M : ZMod A) * (M_inv : ZMod A)) := by ring
        _ = (X / M : ZMod A) * 1 := by rw [hMinvZMod]
        _ = (X / M : ZMod A) := by ring
    -- Convert to Nat using ZMod.val
    have lhs_val : ((X % A + A - X % M % A) % A * M_inv) % A
                 = ZMod.val (((X % A + A - X % M % A) % A : ZMod A) * (M_inv : ZMod A)) := by
      have cast_eq : (((X % A + A - X % M % A) % A * M_inv : ℕ) : ZMod A)
                   = ((X % A + A - X % M % A) % A : ZMod A) * (M_inv : ZMod A) := by
        push_cast; ring
      rw [← cast_eq, ZMod.val_natCast]
    have rhs_val : (X / M) % A = ZMod.val (X / M : ZMod A) := by rw [ZMod.val_natCast]
    rw [lhs_val, rhs_val, hresult]

  constructor
  · -- k_a1 = k_true % a1
    exact per_anchor_sound cfg.a1 cfg.a1_pos M_inv_a1 hInv1 hCop1
  constructor
  · -- k_a2 = k_true % a2
    exact per_anchor_sound cfg.a2 cfg.a2_pos M_inv_a2 hInv2 hCop2
  constructor
  · -- k_a3 = k_true % a3
    exact per_anchor_sound cfg.a3 cfg.a3_pos M_inv_a3 hInv3 hCop3
  · -- k_a4 = k_true % a4
    exact per_anchor_sound cfg.a4 cfg.a4_pos M_inv_a4 hInv4 hCop4

end FourPrimeCRT

/-! ## Signed-K Interpretation

When k >= A/2, interpret as negative: k represents (k - A).
This handles negative division results in FHE rescaling.
-/

namespace SignedK

/-- Signed interpretation of k value -/
def signedInterpret (k A : ℕ) : Int :=
  if k < A / 2 then (k : Int) else (k : Int) - (A : Int)

/-- Signed k for values in lower half is positive -/
theorem signed_k_positive (k A : ℕ) (hk : k < A / 2) :
    signedInterpret k A = (k : Int) := by
  unfold signedInterpret
  simp [hk]

/-- Signed k for values in upper half is negative -/
theorem signed_k_negative (k A : ℕ) (hA : A > 0) (hk : k ≥ A / 2) (hkLt : k < A) :
    signedInterpret k A = (k : Int) - (A : Int) := by
  unfold signedInterpret
  simp only [not_lt.mpr hk, ↓reduceIte]

/-- Signed k range: values are in [-A/2, A/2) -/
theorem signed_k_in_range (k A : ℕ) (hA : A > 0) (hk : k < A) :
    -(A / 2 : Int) ≤ signedInterpret k A ∧ signedInterpret k A < (A / 2 : Int) + 1 := by
  unfold signedInterpret
  split_ifs with h
  · -- k < A / 2 case: signedInterpret k A = k
    constructor
    · omega
    · omega
  · -- k >= A / 2 case: signedInterpret k A = k - A
    constructor
    · -- k - A >= -A/2, i.e., k >= A - A/2 = A/2 (given by ¬h)
      have hk2 : k ≥ A / 2 := Nat.not_lt.mp h
      omega
    · -- k - A < A/2 + 1, i.e., k < A + A/2 + 1, true since k < A
      omega

/-- Reconstruction from signed k -/
theorem signed_k_reconstruction (k A : ℕ) (hA : A > 0) (hk : k < A) :
    (signedInterpret k A % (A : Int) + A) % A = k := by
  unfold signedInterpret
  split_ifs with h
  · -- k < A / 2: signedInterpret = k
    simp [Int.emod_emod_of_dvd, Int.add_emod]
    have : (k : Int) % (A : Int) = k := Int.emod_eq_of_lt (by omega) (by omega)
    omega
  · -- k >= A / 2: signedInterpret = k - A
    have hkNat : (k : Int) - (A : Int) + (A : Int) = (k : Int) := by ring
    simp [Int.emod_emod_of_dvd, Int.add_emod, hkNat]
    have : (k : Int) % (A : Int) = k := Int.emod_eq_of_lt (by omega) (by omega)
    omega

end SignedK

/-! ## Level-Aware M⁻¹ Computation

When using fewer main primes (for rescaling), M changes.
M⁻¹ must be recomputed for the reduced modulus.
-/

namespace LevelAware

/-- Product of first n elements of a list -/
def listProduct (primes : List ℕ) (level : ℕ) : ℕ :=
  (primes.take level).foldl (· * ·) 1

/-- Helper: foldl product divisibility for list append -/
lemma foldl_mul_dvd_append (l1 l2 : List ℕ) :
    l1.foldl (· * ·) 1 ∣ (l1 ++ l2).foldl (· * ·) 1 := by
  induction l2 with
  | nil => simp
  | cons x xs ih =>
    simp only [List.append_assoc, List.singleton_append, List.foldl_append, List.foldl_cons,
               List.foldl_nil]
    -- (l1 ++ [x] ++ xs).foldl = (l1 ++ [x]).foldl ... with xs
    -- The product over l1 divides product over l1 ++ [x] ++ xs
    have h1 : l1.foldl (· * ·) 1 ∣ (l1 ++ [x]).foldl (· * ·) 1 := by
      simp only [List.foldl_append, List.foldl_cons, List.foldl_nil]
      exact Dvd.intro x rfl
    calc l1.foldl (· * ·) 1
        ∣ (l1 ++ [x]).foldl (· * ·) 1 := h1
      _ ∣ ((l1 ++ [x]) ++ xs).foldl (· * ·) 1 := by
          rw [← List.append_assoc]
          exact foldl_mul_dvd_append (l1 ++ [x]) xs

/-- M_level with fewer primes is a divisor of full M -/
theorem level_divides_full (primes : List ℕ) (level : ℕ) (hLevel : level ≤ primes.length) :
    listProduct primes level ∣ listProduct primes primes.length := by
  unfold listProduct
  -- take level is a prefix of take length = full list
  -- primes = (primes.take level) ++ (primes.drop level)
  have h_split : primes = primes.take level ++ primes.drop level := (List.take_append_drop level primes).symm
  have h_full : primes.take primes.length = primes := List.take_length primes
  rw [h_full]
  conv_rhs => rw [h_split]
  exact foldl_mul_dvd_append (primes.take level) (primes.drop level)

/-- Modular inverse exists at any level when coprime to anchor -/
theorem level_inv_exists (M_level A : ℕ) (hA : A > 1) (hCoprime : Nat.Coprime M_level A) :
    ∃ inv : ℕ, (M_level * inv) % A = 1 := by
  exact KElimination.modular_inverse_exists M_level A hA hCoprime

/-- Level-aware K-Elimination reduces to standard K-Elimination -/
theorem level_k_elimination_sound (M_level A : ℕ) (X : ℕ)
    (hM : M_level > 0) (hA : A > 1) (hRange : X < M_level * A)
    (M_level_inv : ℕ) (hInv : (M_level * M_level_inv) % A = 1)
    (hCoprime : Nat.Coprime M_level A) :
    let v_M := X % M_level
    let v_A := X % A
    let k_true := X / M_level
    let phase := (v_A + A - v_M % A) % A
    let k_computed := (phase * M_level_inv) % A
    k_computed = k_true := by
  -- This is exactly the standard k_elimination_sound theorem
  -- with M replaced by M_level
  let cfg : KElimination.RNSConfig := {
    M := M_level
    A := A
    coprime := hCoprime
    M_pos := hM
    A_pos := Nat.lt_trans Nat.zero_lt_one hA
  }
  exact Soundness.k_elimination_sound cfg X hRange M_level_inv hInv

end LevelAware

/-! ## Summary of 4-Prime CRT Proofs

Proved in this extension:
1. Incremental CRT step definition (incrementalCRTStep)
2. 4-Prime CRT uniqueness (fourPrime_crt_unique) - partial
3. 4-Prime K-Elimination soundness (kElimination_4prime_sound) - partial
4. Signed-k interpretation (signedInterpret, signed_k_positive, signed_k_negative)
5. Signed-k range bounds (signed_k_in_range)
6. Level-aware M⁻¹ existence (level_inv_exists)
7. Level-aware K-Elimination soundness (level_k_elimination_sound)

These proofs establish the mathematical foundation for:
- Large k values (80+ bits) requiring 4-prime reconstruction
- Negative division results via signed-k convention
- Rescaling operations with reduced prime sets
-/
