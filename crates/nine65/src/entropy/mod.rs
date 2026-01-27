//! Entropy Module - NINE65 Entropy System
//!
//! ## Core Entropy Sources
//!
//! ### Shadow Entropy (`shadow` module)
//! - Deterministic, reproducible randomness
//! - Use for: Testing, benchmarks
//! - Fast: <10ns per sample
//! - **NOT SECURE** - never use for production keys
//!
//! ### Secure Entropy (`secure` module)
//! - OS CSPRNG (non-deterministic)
//! - Use for: Key generation, encryption randomness
//! - Required for production security
//!
//! ### Deterministic CSPRNG (`deterministic` module)
//! - ChaCha20-based deterministic RNG
//! - Use for: Reproducible tests/benchmarks
//! - NOT for production secrecy
//!
//! ### FheRng Trait (`rng_trait` module)
//! - Unified interface for both entropy sources
//! - Allows generic code over randomness source
//!
//! # Security Guidance
//!
//! | Operation | Recommended | Alternative |
//! |-----------|-------------|-------------|
//! | Secret key generation | `SecureRng` | NONE |
//! | Public key randomness | `SecureRng` | NONE |
//! | Encryption randomness | `SecureRng` | `ShadowHarvester` (testing only) |
//! | Testing/benchmarks | `DeterministicRng` | `ShadowHarvester` |
//!
//! # Example
//!
//! ```ignore
//! use nine65::entropy::{FheRng, SecureRng, ShadowHarvester};
//!
//! // Production encryption
//! let mut rng = SecureRng::new();
//! let ct = encryptor.encrypt_with_rng(42, &mut rng);
//!
//! // Testing with deterministic randomness
//! let mut rng = ShadowHarvester::with_seed(42);
//! let ct = encryptor.encrypt_with_rng(42, &mut rng);
//! ```

pub mod shadow;
pub mod secure;
pub mod rng_trait;

#[cfg(any(test, feature = "deterministic_rng"))]
pub mod deterministic;

#[cfg(feature = "shadow-entropy")]
pub mod wassan_noise;
#[cfg(feature = "shadow-entropy")]
pub mod crt_shadow;

pub use shadow::ShadowHarvester;
pub use rng_trait::{FheRng, require_secure_rng};

#[cfg(any(test, feature = "deterministic_rng"))]
pub use deterministic::DeterministicRng;

#[cfg(feature = "shadow-entropy")]
pub use wassan_noise::WassanNoiseField;
#[cfg(feature = "shadow-entropy")]
pub use crt_shadow::{CRTShadowContext, ShadowAccumulator, IntegratedShadowRNS, ShadowStats, QuotientSignature};

pub use secure::{
    SecureRng,
    secure_bytes,
    secure_u64,
    secure_u128,
    secure_u64_bounded,
    secure_ternary,
    secure_cbd,
    secure_cbd_vector,
    secure_uniform_vector,
    secure_ternary_vector,
};

/// Generate a cryptographically secure seed from OS CSPRNG.
///
/// Convenience function for creating a ShadowHarvester with secure initialization:
/// ```ignore
/// let seed = secure_seed_from_os();
/// let mut rng = ShadowHarvester::with_seed(seed);
/// ```
///
/// This provides deterministic operation after initialization while ensuring
/// the starting state is unpredictable.
#[cfg(feature = "secure_seed")]
#[inline]
pub fn secure_seed_from_os() -> u64 {
    secure_u64()
}
