use generic_array::{GenericArray, ArrayLength};
use keystream::{KeyStream, SeekableKeyStream};
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
    type KeyLength: ArrayLength<u8>;
    type MacLength: ArrayLength<u8>;
    type AsymmetricKey: Curve;
    type Stream: KeyStream + SeekableKeyStream;
    type Collector;

    fn mu(shared: &SharedSecret<Self::AsymmetricKey>) -> Self::Collector;

    fn chain<T>(collector: Self::Collector, data: T) -> Self::Collector
    where
        T: AsRef<[u8]>;

    fn output(collector: Self::Collector) -> GenericArray<u8, Self::MacLength>;

    fn rho(shared: &SharedSecret<Self::AsymmetricKey>) -> Self::Stream;

    fn pi(shared: &SharedSecret<Self::AsymmetricKey>) -> Self::Stream;

    fn tau(public_key: Self::AsymmetricKey) -> SharedSecret<Self::AsymmetricKey>;

    fn blinding(
        public_key: &Self::AsymmetricKey,
        shared: &SharedSecret<Self::AsymmetricKey>,
    ) -> SharedSecret<Self::AsymmetricKey>;
}

impl<A, C, D, S> Sphinx for (A, C, D, S)
where
    A: Curve,
    C: Mac + NewMac,
    D: Default + Update + FixedOutput<OutputSize = <<A as Curve>::Scalar as LineValid>::Length>,
    S: PseudoRandomStream<C::OutputSize> + SeekableKeyStream,
{
    type KeyLength = C::KeySize;
    type MacLength = C::OutputSize;
    type AsymmetricKey = A;
    type Stream = S;
    type Collector = C;

    fn mu(shared: &SharedSecret<Self::AsymmetricKey>) -> Self::Collector {
        let mut collector = C::new_varkey(b"mu").unwrap();
        collector.update(shared);
        let key = collector.finalize().into_bytes();
        C::new_varkey(&key).unwrap()
    }

    fn chain<T>(collector: Self::Collector, data: T) -> Self::Collector
    where
        T: AsRef<[u8]>,
    {
        let mut collector = collector;
        collector.update(data.as_ref());
        collector
    }

    fn output(collector: Self::Collector) -> GenericArray<u8, Self::MacLength> {
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
    ) -> SharedSecret<Self::AsymmetricKey> {
        D::default()
            .chain(public_key.compress().clone_line().as_ref())
            .chain(shared)
            .finalize_fixed()
    }
}
