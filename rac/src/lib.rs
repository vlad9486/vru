#![forbid(unsafe_code)]
#![no_std]

pub extern crate generic_array;

mod line;
pub use self::line::{LineValid, Line};

mod concat;
pub use self::concat::Concat;

mod elliptic;
pub use self::elliptic::{Scalar, Curve, Signature};

#[cfg(feature = "secp256k1")]
mod secp256k1_m;

#[cfg(feature = "curve25519-dalek")]
mod curve25519_dalek_m;
