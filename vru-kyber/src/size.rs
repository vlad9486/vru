use core::ops::{Mul, Range};
use rac::generic_array::{
    ArrayLength,
    typenum::{self, Unsigned},
};
use super::{coefficient::Coefficient, poly_inner::PolyInner};

pub trait PolySize {
    type C: ArrayLength<Coefficient>;
    type CompressedBytes: ArrayLength<u8>;
    type Bytes: ArrayLength<u8>;
    type Omegas: ArrayLength<Coefficient>;

    fn range() -> Range<usize>;
    fn c_range() -> Range<usize>;
}

pub trait PolyVectorSize<S>
where
    S: PolySize,
{
    type K: ArrayLength<PolyInner<S>>;
    type Eta: ArrayLength<u8>;
}

impl<U> PolySize for U
where
    U: Unsigned + Mul<typenum::U8> + Mul<typenum::U3> + Mul<typenum::U13> + Mul<typenum::U4>,
    <U as Mul<typenum::U8>>::Output: ArrayLength<Coefficient>,
    <U as Mul<typenum::U3>>::Output: ArrayLength<u8>,
    <U as Mul<typenum::U13>>::Output: ArrayLength<u8>,
    <U as Mul<typenum::U4>>::Output: ArrayLength<Coefficient>,
{
    type C = <U as Mul<typenum::U8>>::Output;
    type CompressedBytes = <U as Mul<typenum::U3>>::Output;
    type Bytes = <U as Mul<typenum::U13>>::Output;
    type Omegas = <U as Mul<typenum::U4>>::Output;

    fn range() -> Range<usize> {
        0..U::USIZE
    }

    fn c_range() -> Range<usize> {
        0..(U::USIZE * 8)
    }
}

impl<S> PolyVectorSize<S> for typenum::U2
where
    S: PolySize + Mul<typenum::U10>,
    <S as Mul<typenum::U10>>::Output: ArrayLength<u8>,
{
    type K = Self;
    type Eta = <S as Mul<typenum::U10>>::Output;
}

impl<S> PolyVectorSize<S> for typenum::U3
where
    S: PolySize + Mul<typenum::U8>,
    <S as Mul<typenum::U8>>::Output: ArrayLength<u8>,
{
    type K = Self;
    type Eta = <S as Mul<typenum::U8>>::Output;
}

impl<S> PolyVectorSize<S> for typenum::U4
where
    S: PolySize + Mul<typenum::U6>,
    <S as Mul<typenum::U6>>::Output: ArrayLength<u8>,
{
    type K = Self;
    type Eta = <S as Mul<typenum::U6>>::Output;
}
