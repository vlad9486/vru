#![forbid(unsafe_code)]
#![allow(non_shorthand_field_patterns)]
#![no_std]

#[cfg(test)]
extern crate std;

#[cfg(all(test, feature = "serde"))]
mod test;

mod path;
mod sphinx;
mod packet;

pub use rac;
pub use self::sphinx::{SharedSecret, Sphinx};
pub use self::packet::{AuthenticatedMessage, LocalData, GlobalData, Processed};
