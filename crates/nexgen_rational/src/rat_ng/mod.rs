//! NexGen Rational Number Module
//!
//! Integer-only exact rational arithmetic with adaptive normalization.

pub mod types;
pub mod error;
pub mod normalize;
pub mod policy;
pub mod ops;

pub use types::{NexGenRat, DenState, DivOut};
pub use error::ArithmeticError;
pub use crate::exact_coeff::ExactCoeff;
