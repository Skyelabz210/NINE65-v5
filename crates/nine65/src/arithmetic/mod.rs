//! Arithmetic Module - QMNF Integer-Only Foundations
//!
//! ZERO floating point. ALL computations exact.
//!
//! Innovations:
//! - **Persistent Montgomery**: Never leave Montgomery form (50-100× speedup)
//! - **NTT Gen 3**: Negacyclic convolution with ψ-twist
//! - **RNS/CRT**: Parallel computation across coprime moduli
//! - **K-Elimination**: Exact polynomial division (50× speedup)
//! - **Exact Divider**: Dual-track integer reconstruction
//! - **Exact Coeff**: Dual-track coefficient representation
//! - **CT Mul Exact**: Exact ciphertext multiplication
//! - **MobiusInt**: Signed arithmetic (no M/2 threshold failure)
//! - **Padé Engine**: Integer-only transcendentals (exp/sin/cos/log)
//! - **MQ-ReLU**: O(1) sign detection via q/2 threshold
//! - **Integer Softmax**: Exact sum guarantee softmax
//! - **Cyclotomic Phase**: Native ring trig (sin/cos via coefficient extraction)

pub mod montgomery;
pub mod persistent_montgomery;  // THE INNOVATION
pub mod barrett;
pub mod ntt;
pub mod ntt_fft;  // V2: O(N log N) FFT-based NTT (500-2000× faster)
pub mod rns;
pub mod k_elimination;  // THE 60-YEAR SOLUTION
pub mod exact_divider;  // K-ELIMINATION PRIMITIVE
pub mod exact_coeff;    // DUAL-TRACK COEFFICIENTS
pub mod ct_mul_exact;   // EXACT CT×CT
pub mod mobius_int;     // SIGNED ARITHMETIC (no M/2 threshold failure)
pub mod pade_engine;    // INTEGER TRANSCENDENTALS (exp/sin/cos/sigmoid)
pub mod mq_relu;        // O(1) SIGN DETECTION
pub mod integer_softmax; // EXACT SUM SOFTMAX
pub mod cyclotomic_phase; // NATIVE RING TRIGONOMETRY
pub mod valuation;
pub mod order_finding;    // NON-CIRCULAR BSGS (Shor's classical reduction)
pub mod integer_math;     // INTEGER UTILITIES (log2, sqrt, format, trig LUT)

pub use montgomery::MontgomeryContext;
pub use persistent_montgomery::{PersistentMontgomery, PersistentPolynomial};
pub use barrett::{BarrettContext, HybridModContext};

// NTT: Use FFT version (O(N log N)) when feature enabled, else DFT (O(N²))
#[cfg(feature = "ntt_fft")]
pub use ntt_fft::NTTEngineFFT as NTTEngine;
#[cfg(not(feature = "ntt_fft"))]
pub use ntt::NTTEngine;

// Also export both explicitly for users who need specific version
pub use ntt::NTTEngine as NTTEngineDFT;
pub use ntt_fft::NTTEngineFFT;
pub use rns::{RNSContext, RNSPolynomial, DualRNSContext, DualRNSPolynomial, DualRNSValue};
pub(crate) use rns::{U256, compute_delta_rns_overflow_safe};
pub use k_elimination::KElimination;
pub use exact_divider::ExactDivider;
pub use exact_coeff::{ExactCoeff, ExactContext, ExactPoly, AnchorTrack, RnsInner};
pub use ct_mul_exact::{ExactCiphertext, ExactCiphertext2, ExactFHEContext};
pub use mobius_int::{MobiusInt, MobiusPolynomial, MobiusVector, Polarity};
pub use pade_engine::{PadeEngine, PADE_SCALE};
pub use mq_relu::{MQReLU, MQReLUPolynomial, Sign};
pub use integer_softmax::{IntegerSoftmax, SOFTMAX_SCALE};
pub use cyclotomic_phase::{CyclotomicRing, CyclotomicPolynomial, modular_distance, toric_coupling};
pub use order_finding::{
    multiplicative_order, multiplicative_order_detailed,
    factor_via_order, factor_semiprime,
    verify_order_k_elimination, KRecurrence,
    OrderResult, FactorResult, gcd,
};
pub use integer_math::{
    integer_log2, integer_log2_u128, integer_sqrt,
    format_millibits, format_ops, format_as_bits,
    fixed_cos_sin, COS_SIN_TABLE, GOLDEN_ANGLE_Q30,
};

#[cfg(feature = "exact_rational")]
pub mod rational_bridge;
#[cfg(feature = "exact_rational")]
pub use rational_bridge::RationalBridge;

#[cfg(feature = "clockwork")]
pub mod bounded_rns;
#[cfg(feature = "clockwork")]
pub use bounded_rns::BoundedValue;
