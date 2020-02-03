#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "vru-noise-macros")]
extern crate vru_noise_macros;

mod state;
mod handshake;
#[cfg(any(feature = "vru-noise-macros", test))]
pub mod handshakes;
#[cfg(test)]
mod test;

pub use generic_array::typenum;

#[cfg(feature = "vru-noise-macros")]
pub use vru_noise_macros::{Pattern, Handshake};

pub use self::state::{State, StateError, CipherError, CipherPair, NoiseAlgorithm, CipherAlgorithm};
pub use self::state::{
    HashLength, EncryptedPayload, AeadKey, ChainingKey, CompressedCurve, Rotor, SimpleRotor,
};

#[cfg(feature = "std")]
pub use self::handshake::HandshakeError;

pub use self::handshake::{HandshakeState, History, BaseHistory};
pub use self::handshake::{Pattern, PatternError, BasePattern};
pub use self::handshake::{Token, Payload, EncryptedPoint, Point, MixDh, MixPsk};
