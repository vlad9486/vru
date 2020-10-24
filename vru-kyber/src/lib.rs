#![no_std]
#![forbid(unsafe_code)]

mod coefficient;
mod size;
mod poly_inner;
mod poly;

pub use self::poly::{Poly, Ntt};
