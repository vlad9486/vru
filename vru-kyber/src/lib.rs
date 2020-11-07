#![no_std]
#![forbid(unsafe_code)]

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
