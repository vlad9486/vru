#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
#[macro_use]
extern crate std;
#[cfg(test)]
mod tests;

mod config;
mod hash;
mod cipher_state;
#[allow(non_shorthand_field_patterns)]
mod symmetric_state;

pub use self::config::Config;
pub use self::cipher_state::{Tag, Aead, ChainingKey, Rotor, Cipher};
pub use self::symmetric_state::{Key, Authenticated, SymmetricState};

pub use generic_array::typenum;
