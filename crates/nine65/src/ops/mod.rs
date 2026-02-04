//! Operations Module - BFV FHE Operations
//!
//! Provides:
//! - Encryption and decryption
//! - Homomorphic operations (add, mul, etc.)
//! - RNS-based multiplication for ct×ct
//! - Noise management
//! - Neural network operations
//! - Galois automorphisms for SIMD slot rotations
//! - CRT batching for SIMD packing (N/2 slots per ciphertext)
//! - Parallel encrypt/decrypt for throughput

pub mod batch;
pub mod encrypt;
pub mod homomorphic;
pub mod parallel;
pub mod rns_mul;
pub mod rns_fhe;
pub mod neural;
pub mod galois;
pub mod gso_fhe;

pub use batch::BatchEncoder;
pub use encrypt::{BFVEncoder, BFVEncryptor, BFVDecryptor, Ciphertext};
pub use homomorphic::{BFVEvaluator, TrackedEvaluator};
pub use parallel::{ParallelEncryptor, ParallelDecryptor};
pub use rns_mul::RNSEvaluator;
pub use rns_fhe::{RNSFHEContext, RNSCiphertext, RNSKeySet, RNSSecretKey, RNSPublicKey, RNSEvalKey};
pub use neural::{FHENeuralEvaluator, ActivationType, DenseLayer, NeuralNetwork};
pub use galois::{GaloisEngine, GaloisKey, GaloisKeySet, GaloisEvaluator};
pub use gso_fhe::{GSOFHEContext, GSOCiphertext, NoiseEstimate, NoiseStats, AttractorBasin, GSOSwarm};
