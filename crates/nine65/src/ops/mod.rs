//! Operations Module - BFV FHE Operations
//!
//! Provides:
//! - Encryption and decryption
//! - Homomorphic operations (add, mul, etc.)
//! - RNS-based multiplication for ct×ct
//! - Noise management
//! - Neural network operations (QMNF nonlinear innovations)

pub mod encrypt;
pub mod homomorphic;
pub mod rns_mul;
pub mod rns_fhe;
pub mod neural;
pub mod gso_fhe;

pub use encrypt::{BFVEncoder, BFVEncryptor, BFVDecryptor, Ciphertext};
pub use homomorphic::BFVEvaluator;
pub use rns_mul::RNSEvaluator;
pub use rns_fhe::{RNSFHEContext, RNSCiphertext, RNSKeySet, RNSSecretKey, RNSPublicKey, RNSEvalKey};
pub use neural::{FHENeuralEvaluator, ActivationType, DenseLayer, NeuralNetwork};
pub use gso_fhe::{GSOFHEContext, GSOCiphertext, NoiseEstimate, NoiseStats, AttractorBasin, GSOSwarm};
