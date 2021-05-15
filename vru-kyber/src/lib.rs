#![no_std]
#![forbid(unsafe_code)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::identity_op)]

#[cfg(test)]
#[macro_use]
extern crate std;

mod coefficient;
mod size;
mod poly_inner;
mod poly;

mod indcpa;
mod kem;

pub use self::kem::Kyber;
pub use pq_kem::Kem;
