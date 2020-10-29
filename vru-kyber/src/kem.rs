use core::marker::PhantomData;
use pq_kem::Kem;
use rac::{LineValid, generic_array::{ArrayLength, typenum}};
use super::{
    size::PolySize,
    poly::Poly,
    indcpa,
};

pub struct Kyber<S, W>(PhantomData<(S, W)>)
where
    S: PolySize,
    W: ArrayLength<Poly<S, typenum::B1>>;

/*impl<S, W> Kem for Kyber<S, W>
where
    S: PolySize,
    W: ArrayLength<Poly<S, typenum::B1>>,
    indcpa::PublicKey<S, W>: LineValid,
{
    type PublicKey = indcpa::PublicKey<S, W>;
}*/
