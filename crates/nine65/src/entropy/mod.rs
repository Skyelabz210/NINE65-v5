//! Entropy Module - NINE65 Entropy System
//!
//! Two core entropy sources:
//!
//! ## Shadow Entropy (`shadow` module)
//! - Deterministic, reproducible randomness
//! - Use for: Testing, benchmarks, noise sampling
//! - Fast: <10ns per sample
//!
//! ## Secure Entropy (`secure` module)
//! - OS CSPRNG (non-deterministic)
//! - Use for: Secret key generation, public key randomness
//! - Required for production security
//!
//! # Security Guidance
//!
//! | Operation | Use This |
//! |-----------|----------|
//! | Secret key generation | `secure::*` |
//! | Public key 'a' polynomial | `secure::*` |
//! | Error/noise sampling | `shadow::*` or `secure::*` |
//! | Testing/benchmarks | `shadow::*` |
//! | Reproducible results | `shadow::*` |

pub mod shadow;
pub mod secure;

#[cfg(feature = "shadow-entropy")]
pub mod wassan_noise;
#[cfg(feature = "shadow-entropy")]
pub mod crt_shadow;

pub use shadow::ShadowHarvester;

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
