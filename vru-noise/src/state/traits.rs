use super::noise_nonce::NoiseNonce;

use core::marker::PhantomData;
use rac::{LineValid, Line, Concat, Curve};
use digest::{Input, BlockInput, FixedOutput, Reset};
use generic_array::{
    GenericArray, ArrayLength,
    typenum::{Unsigned, Bit},
};
use aead::{NewAead, Aead};

type HkdfLength<Ca> = <<Ca as CipherAlgorithm>::HkdfSplit as HkdfSplit>::Length;
pub type ChainingKey<Ca> = GenericArray<u8, HkdfLength<Ca>>;
pub type HashLength<Na> = <<Na as NoiseAlgorithm>::MixHash as MixHash>::Length;
pub type Tag<Ca> = GenericArray<u8, <<Ca as CipherAlgorithm>::Aead as Aead>::TagSize>;
pub type EncryptedPayload<Na, P> = Concat<
    GenericArray<u8, <P as LineValid>::Length>,
    Tag<<Na as NoiseAlgorithm>::CipherAlgorithm>,
>;

pub type AeadKey<Ca> = GenericArray<u8, <<Ca as CipherAlgorithm>::Aead as NewAead>::KeySize>;
pub type CompressedCurve<C> = GenericArray<u8, <C as Curve>::CompressedLength>;

pub trait NoiseAlgorithm {
    type CipherAlgorithm: CipherAlgorithm;
    type Curve: Curve;
    type HashDh: Bit;
    type MixHash: MixHash<Length = HkdfLength<Self::CipherAlgorithm>>;
}

impl<K, D, C, F> NoiseAlgorithm for (K, D, C, F)
where
    K: NewAead + Aead + NoiseNonce + Clone,
    D: MixHash<Length = <D as HkdfSplit>::Length> + HkdfSplit,
    C: Curve,
    F: Bit,
{
    type CipherAlgorithm = (K, D);
    type Curve = C;
    type HashDh = F;
    type MixHash = D;
}

pub trait CipherAlgorithm {
    type Aead: NewAead + Aead + NoiseNonce + Clone;
    type HkdfSplit: HkdfSplit;

    fn truncate(hash: &ChainingKey<Self>) -> AeadKey<Self>;

    fn split_2<T>(salt: &ChainingKey<Self>, data: &T) -> (ChainingKey<Self>, AeadKey<Self>)
    where
        T: AsRef<[u8]>;

    fn split_3<T>(
        salt: &ChainingKey<Self>,
        data: &T,
    ) -> (ChainingKey<Self>, AeadKey<Self>, AeadKey<Self>)
    where
        T: AsRef<[u8]>;
}

impl<K, D> CipherAlgorithm for (K, D)
where
    K: NewAead + Aead + NoiseNonce + Clone,
    D: HkdfSplit,
{
    type Aead = K;
    type HkdfSplit = D;

    fn truncate(hash: &ChainingKey<Self>) -> AeadKey<Self> {
        let input_length = <HkdfLength<Self> as Unsigned>::to_usize();
        let output_length = <<Self::Aead as NewAead>::KeySize as Unsigned>::to_usize();
        assert!(output_length <= input_length);

        let mut a = GenericArray::default();
        a[..output_length].clone_from_slice(&hash[..output_length]);
        a
    }

    fn split_2<T>(salt: &ChainingKey<Self>, data: &T) -> (ChainingKey<Self>, AeadKey<Self>)
    where
        T: AsRef<[u8]>,
    {
        let (a, b) = Self::HkdfSplit::hkdf_split_2(Some(salt), data);
        (a, Self::truncate(&b))
    }

    fn split_3<T>(
        salt: &ChainingKey<Self>,
        data: &T,
    ) -> (ChainingKey<Self>, AeadKey<Self>, AeadKey<Self>)
    where
        T: AsRef<[u8]>,
    {
        let (a, b, c) = Self::HkdfSplit::hkdf_split_3(Some(salt), data);
        (a, Self::truncate(&b), Self::truncate(&c))
    }
}

pub trait Rotor<A>
where
    A: CipherAlgorithm,
{
    const INTERVAL: u64;

    fn new(key: &AeadKey<A>) -> Self;

    fn rotate(&mut self, chaining_key: &mut ChainingKey<A>, key: &mut A::Aead);
}

pub struct SimpleRotor<A>(PhantomData<A>)
where
    A: CipherAlgorithm;

impl<A> Clone for SimpleRotor<A>
where
    A: CipherAlgorithm,
{
    fn clone(&self) -> Self {
        SimpleRotor(PhantomData)
    }
}

impl<A> Rotor<A> for SimpleRotor<A>
where
    A: CipherAlgorithm,
{
    const INTERVAL: u64 = 0xffffffffffffffff;

    fn new(key: &AeadKey<A>) -> Self {
        let _ = key;
        SimpleRotor(PhantomData)
    }

    fn rotate(&mut self, chaining_key: &mut ChainingKey<A>, key: &mut A::Aead) {
        let _ = (chaining_key, key);
    }
}

pub trait MixHash {
    type Length: ArrayLength<u8>;

    fn init<T>(data: &T) -> GenericArray<u8, Self::Length>
    where
        T: AsRef<[u8]>;

    fn mix_hash<T>(hash: &mut GenericArray<u8, Self::Length>, data: &T)
    where
        T: AsRef<[u8]>;
}

impl<D> MixHash for D
where
    D: Input + FixedOutput + Default,
{
    type Length = <D as FixedOutput>::OutputSize;

    fn init<T>(data: &T) -> GenericArray<u8, Self::Length>
    where
        T: AsRef<[u8]>,
    {
        D::default().chain(data).fixed_result()
    }

    fn mix_hash<T>(hash: &mut GenericArray<u8, Self::Length>, data: &T)
    where
        T: AsRef<[u8]>,
    {
        *hash = D::default().chain(&hash).chain(data).fixed_result();
    }
}

pub trait HkdfSplit {
    type Length: ArrayLength<u8>;

    fn hkdf_split_2<S, T>(
        salt: Option<&S>,
        ikm: &T,
    ) -> (
        GenericArray<u8, Self::Length>,
        GenericArray<u8, Self::Length>,
    )
    where
        S: AsRef<[u8]>,
        T: AsRef<[u8]>;

    fn hkdf_split_3<S, T>(
        salt: Option<&S>,
        ikm: &T,
    ) -> (
        GenericArray<u8, Self::Length>,
        GenericArray<u8, Self::Length>,
        GenericArray<u8, Self::Length>,
    )
    where
        S: AsRef<[u8]>,
        T: AsRef<[u8]>;
}

type Hash<D> = GenericArray<u8, <D as FixedOutput>::OutputSize>;

impl<D> HkdfSplit for D
where
    D: Input + BlockInput + FixedOutput + Reset + Default + Clone,
    D::BlockSize: Clone,
    Concat<Hash<D>, Hash<D>>: Line,
    Concat<Concat<Hash<D>, Hash<D>>, Hash<D>>: Line,
{
    type Length = <D as FixedOutput>::OutputSize;

    fn hkdf_split_2<S, T>(
        salt: Option<&S>,
        ikm: &T,
    ) -> (
        GenericArray<u8, Self::Length>,
        GenericArray<u8, Self::Length>,
    )
    where
        S: AsRef<[u8]>,
        T: AsRef<[u8]>,
    {
        use hkdf::Hkdf;

        let (_, hkdf) = match salt {
            None => Hkdf::<D>::extract(None, ikm.as_ref()),
            Some(salt) => Hkdf::<D>::extract(Some(salt.as_ref()), ikm.as_ref()),
        };
        let mut okm = GenericArray::default();
        hkdf.expand(&[], okm.as_mut()).unwrap();
        let Concat(a, b) = Concat::clone_array(&okm);
        (a, b)
    }

    fn hkdf_split_3<S, T>(
        salt: Option<&S>,
        ikm: &T,
    ) -> (
        GenericArray<u8, Self::Length>,
        GenericArray<u8, Self::Length>,
        GenericArray<u8, Self::Length>,
    )
    where
        S: AsRef<[u8]>,
        T: AsRef<[u8]>,
    {
        use hkdf::Hkdf;

        let (_, hkdf) = match salt {
            None => Hkdf::<D>::extract(None, ikm.as_ref()),
            Some(salt) => Hkdf::<D>::extract(Some(salt.as_ref()), ikm.as_ref()),
        };
        let mut okm = GenericArray::default();
        hkdf.expand(&[], okm.as_mut()).unwrap();
        let Concat(Concat(a, b), c) = Concat::clone_array(&okm);
        (a, b, c)
    }
}
