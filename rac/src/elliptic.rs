use generic_array::ArrayLength;
use crate::line::{Array, LineValid};

pub trait Scalar
where
    Self: LineValid,
{
    fn add_ff(&self, rhs: &Self) -> Result<Self, ()>;
    fn sub_ff(&self, rhs: &Self) -> Result<Self, ()>;
    fn mul_ff(&self, rhs: &Self) -> Result<Self, ()>;
    fn inv_ff(&self) -> Result<Self, ()>;
}

pub trait Curve
where
    Self: LineValid,
{
    type Scalar: Scalar;
    type CompressedLength: ArrayLength<u8>;
    type CoordinateLength: ArrayLength<u8>;

    const NAME: &'static str;

    fn base() -> Self;
    fn mul_ec(&self, rhs: &Self) -> Self;
    fn exp_ec(&self, rhs: &Self::Scalar) -> Self;
    fn decompress(packed: &Array<Self::CompressedLength>) -> Result<Self, ()>;
    fn compress(&self) -> Array<Self::CompressedLength>;
    fn x_coordinate(&self) -> Array<Self::CoordinateLength>;
}
