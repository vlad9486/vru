use core::ops::{Mul, Range};
use rac::generic_array::{
    ArrayLength,
    typenum::{self, Unsigned},
};
use super::coefficient::Coefficient;

pub trait PolySize
where
    Self: ArrayLength<u8>,
{
    type C: ArrayLength<Coefficient>;
    type Compressed: ArrayLength<u8>;
    type CompressedSlightly: ArrayLength<u8>;
    type Bytes: ArrayLength<u8>;
    type Omegas: ArrayLength<Coefficient>;

    fn range() -> Range<usize>;
    fn c_range() -> Range<usize>;
}

impl<U> PolySize for U
where
    U: Unsigned
        + ArrayLength<u8>
        + Mul<typenum::U8>
        + Mul<typenum::U3>
        + Mul<typenum::U11>
        + Mul<typenum::U13>
        + Mul<typenum::U4>,
    <U as Mul<typenum::U8>>::Output: ArrayLength<Coefficient>,
    <U as Mul<typenum::U3>>::Output: ArrayLength<u8>,
    <U as Mul<typenum::U11>>::Output: ArrayLength<u8>,
    <U as Mul<typenum::U13>>::Output: ArrayLength<u8>,
    <U as Mul<typenum::U4>>::Output: ArrayLength<Coefficient>,
{
    type C = <U as Mul<typenum::U8>>::Output;
    type Compressed = <U as Mul<typenum::U3>>::Output;
    type CompressedSlightly = <U as Mul<typenum::U11>>::Output;
    type Bytes = <U as Mul<typenum::U13>>::Output;
    type Omegas = <U as Mul<typenum::U4>>::Output;

    fn range() -> Range<usize> {
        0..U::USIZE
    }

    fn c_range() -> Range<usize> {
        0..(U::USIZE * 8)
    }
}
