#![forbid(unsafe_code)]
#![no_std]
#![allow(non_shorthand_field_patterns)]
#![allow(clippy::all)]

pub extern crate generic_array;

mod line;
pub use self::line::{Array, LineValid, Line, LineLike};

mod concat;
pub use self::concat::Concat;

mod elliptic;
pub use self::elliptic::{Scalar, Curve};

mod schnorr;
pub use self::schnorr::{Signature, Schnorr};

#[cfg(feature = "secp256k1")]
mod secp256k1_m;

#[cfg(feature = "curve25519-dalek")]
mod curve25519_dalek_m;
