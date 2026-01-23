//! NINE65 Error Taxonomy
//!
//! Standardized error types derived from Coq proof preconditions.
//! Every error maps to a specific theorem violation.
//!
//! # Theorem Reference
//! Error conditions are derived from:
//! - `KElimination.v` — Division preconditions
//! - `GSOFHE.v` — Noise bounds
//! - `OrderFinding.v` — Coprimality requirements
//! - `MQReLU.v` — Modulus constraints

use thiserror::Error;

/// NINE65 Error Types
///
/// Comprehensive error taxonomy for all innovations.
/// Each variant maps to a specific Coq precondition violation.
#[derive(Debug, Clone, Error)]
pub enum Nine65Error {
    // ═══════════════════════════════════════════════════
    // K-ELIMINATION ERRORS (KElimination.v)
    // ═══════════════════════════════════════════════════

    /// Coprimality violation: gcd(M, A) ≠ 1
    ///
    /// # Theorem Reference
    /// `KElimination.v:kElimination_core` requires coprime moduli
    #[error("coprimality violation: gcd({m}, {a}) = {gcd} ≠ 1")]
    NotCoprime { m: u64, a: u64, gcd: u64 },

    /// Range overflow: X ≥ M * A
    ///
    /// # Theorem Reference
    /// `KElimination.v:kElimination_core` requires X < M * A
    #[error("range overflow: X={x} ≥ M*A={bound}")]
    RangeOverflow { x: u128, bound: u128 },

    /// Modulus zero: M must be > 0
    ///
    /// # Theorem Reference
    /// `KElimination.v` — M > 0 precondition
    #[error("modulus zero: M must be > 0")]
    ModulusZero,

    /// Anchor zero: A must be > 0
    ///
    /// # Theorem Reference
    /// `KElimination.v` — A > 0 precondition
    #[error("anchor zero: A must be > 0")]
    AnchorZero,

    /// Inexact division: divisor does not divide value
    ///
    /// # Theorem Reference
    /// `ExactCoefficient.v:div_exact` requires divisibility
    #[error("inexact division: {value} not divisible by {divisor}")]
    InexactDivision { value: u128, divisor: u64 },

    // ═══════════════════════════════════════════════════
    // GSO-FHE ERRORS (GSOFHE.v)
    // ═══════════════════════════════════════════════════

    /// Noise overflow: exceeded collapse threshold
    ///
    /// # Theorem Reference
    /// `GSOFHE.v:noise_bounded` — noise ≤ threshold
    #[error("noise overflow: {level} > threshold {threshold}")]
    NoiseOverflow { level: u64, threshold: u64 },

    /// Depth exceeded: circuit too deep
    ///
    /// # Theorem Reference
    /// `GSOFHE.v:depth_50_achievable` — depth bounds
    #[error("depth exceeded: {depth} > max {max_depth}")]
    DepthExceeded { depth: u32, max_depth: u32 },

    // ═══════════════════════════════════════════════════
    // ORDER FINDING ERRORS (OrderFinding.v)
    // ═══════════════════════════════════════════════════

    /// Order not found within bound
    ///
    /// # Theorem Reference
    /// `OrderFinding.v:lagrange_bound` — order ≤ N-1
    #[error("order not found: a={a} mod N={n} within bound {bound}")]
    OrderNotFound { a: u64, n: u64, bound: u64 },

    /// Not coprime to modulus (for order finding)
    ///
    /// # Theorem Reference
    /// `OrderFinding.v:lagrange_bound` requires gcd(a, N) = 1
    #[error("not coprime to modulus: gcd({a}, {n}) ≠ 1")]
    NotCoprimeToModulus { a: u64, n: u64 },

    // ═══════════════════════════════════════════════════
    // ARITHMETIC ERRORS
    // ═══════════════════════════════════════════════════

    /// Integer overflow during computation
    ///
    /// # Note
    /// Coq `nat` is unbounded; Rust u64/u128 is not.
    /// This error indicates need for BigUint.
    #[error("integer overflow in {operation}")]
    Overflow { operation: &'static str },

    /// Invalid parameter configuration
    #[error("invalid parameter: {message}")]
    InvalidParameter { message: String },

    // ═══════════════════════════════════════════════════
    // CRYPTOGRAPHIC ERRORS
    // ═══════════════════════════════════════════════════

    /// Decryption failed (noise too high)
    #[error("decryption failed: noise exceeded budget")]
    DecryptionFailed,

    /// Key generation failed
    #[error("key generation failed: {reason}")]
    KeyGenFailed { reason: String },

    /// Security level not met
    #[error("security level not met: {bits} bits < required {required} bits")]
    SecurityLevelNotMet { bits: u32, required: u32 },
}

/// Result type alias for NINE65 operations
pub type Nine65Result<T> = Result<T, Nine65Error>;

impl Nine65Error {
    /// Check if error is recoverable
    pub fn is_recoverable(&self) -> bool {
        matches!(self,
            Nine65Error::NoiseOverflow { .. } |
            Nine65Error::DepthExceeded { .. }
        )
    }

    /// Get error category for logging
    pub fn category(&self) -> &'static str {
        match self {
            Nine65Error::NotCoprime { .. } |
            Nine65Error::RangeOverflow { .. } |
            Nine65Error::ModulusZero |
            Nine65Error::AnchorZero |
            Nine65Error::InexactDivision { .. } => "K-Elimination",

            Nine65Error::NoiseOverflow { .. } |
            Nine65Error::DepthExceeded { .. } => "GSO-FHE",

            Nine65Error::OrderNotFound { .. } |
            Nine65Error::NotCoprimeToModulus { .. } => "Order Finding",

            Nine65Error::Overflow { .. } |
            Nine65Error::InvalidParameter { .. } => "Arithmetic",

            Nine65Error::DecryptionFailed |
            Nine65Error::KeyGenFailed { .. } |
            Nine65Error::SecurityLevelNotMet { .. } => "Cryptographic",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Nine65Error::NotCoprime { m: 10, a: 15, gcd: 5 };
        assert!(err.to_string().contains("coprimality violation"));
        assert_eq!(err.category(), "K-Elimination");
    }

    #[test]
    fn test_error_recoverable() {
        let recoverable = Nine65Error::NoiseOverflow { level: 100, threshold: 50 };
        let not_recoverable = Nine65Error::ModulusZero;

        assert!(recoverable.is_recoverable());
        assert!(!not_recoverable.is_recoverable());
    }
}
