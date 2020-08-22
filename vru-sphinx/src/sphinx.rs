use generic_array::{GenericArray, ArrayLength};
use keystream::SeekableKeyStream;
use rac::{LineValid, Curve};
use crypto_mac::{Mac, NewMac};
use digest::{Update, FixedOutput};

pub trait PseudoRandomStream<T>
where
    T: ArrayLength<u8>,
{
    fn seed(v: GenericArray<u8, T>) -> Self;
}

pub type SharedSecret<A> = GenericArray<u8, <<A as Curve>::Scalar as LineValid>::Length>;

pub trait Sphinx {
    type MacLength: ArrayLength<u8>;
    type AsymmetricKey: Curve;
    type Stream: SeekableKeyStream;

    fn mu<'a, I>(
        shared: &SharedSecret<Self::AsymmetricKey>,
        data: I,
    ) -> GenericArray<u8, Self::MacLength>
    where
        I: Iterator<Item = &'a [u8]>;

    fn rho(shared: &SharedSecret<Self::AsymmetricKey>) -> Self::Stream;

    fn pi(shared: &SharedSecret<Self::AsymmetricKey>) -> Self::Stream;

    fn tau(public_key: Self::AsymmetricKey) -> SharedSecret<Self::AsymmetricKey>;

    fn blinding(
        public_key: &Self::AsymmetricKey,
        shared: &SharedSecret<Self::AsymmetricKey>,
    ) -> <Self::AsymmetricKey as Curve>::Scalar;
}

impl<A, C, D, S> Sphinx for (A, C, D, S)
where
    A: Curve,
    C: Mac + NewMac,
    D: Default + Update + FixedOutput<OutputSize = <<A as Curve>::Scalar as LineValid>::Length>,
    S: PseudoRandomStream<C::OutputSize> + SeekableKeyStream,
{
    type MacLength = C::OutputSize;
    type AsymmetricKey = A;
    type Stream = S;

    fn mu<'a, I>(
        shared: &SharedSecret<Self::AsymmetricKey>,
        data: I,
    ) -> GenericArray<u8, Self::MacLength>
    where
        I: Iterator<Item = &'a [u8]>,
    {
        let mut collector = C::new_varkey(b"mu").unwrap();
        collector.update(shared);
        let key = collector.finalize().into_bytes();
        let mut collector = C::new_varkey(&key).unwrap();
        data.for_each(|s| collector.update(s));
        collector.finalize().into_bytes()
    }

    fn rho(shared: &SharedSecret<Self::AsymmetricKey>) -> Self::Stream {
        let mut collector = C::new_varkey(b"rho").unwrap();
        collector.update(shared);
        let key = collector.finalize().into_bytes();
        S::seed(key)
    }

    fn pi(shared: &SharedSecret<Self::AsymmetricKey>) -> Self::Stream {
        let mut collector = C::new_varkey(b"um").unwrap();
        collector.update(shared);
        let key = collector.finalize().into_bytes();
        S::seed(key)
    }

    fn tau(public_key: Self::AsymmetricKey) -> SharedSecret<Self::AsymmetricKey> {
        D::default()
            .chain(public_key.compress().clone_line().as_ref())
            .finalize_fixed()
    }

    fn blinding(
        public_key: &Self::AsymmetricKey,
        shared: &SharedSecret<Self::AsymmetricKey>,
    ) -> <Self::AsymmetricKey as Curve>::Scalar {
        let r = D::default()
            .chain(public_key.compress().clone_line().as_ref())
            .chain(shared)
            .finalize_fixed();
        // safe to unwrap because array is result if hashing
        LineValid::try_clone_array(&r).unwrap()
    }
}
