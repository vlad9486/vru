use {
    digest::{Update, BlockInput, FixedOutput, Reset},
    aead::NewAead,
};
use generic_array::{
    GenericArray, ArrayLength,
    sequence::GenericSequence,
    typenum::{self, Unsigned},
};
use core::ops::Mul;

pub trait MixHash
where
    Self: Sized,
{
    type L: ArrayLength<u8>;
    type B: ArrayLength<u8>;

    fn init(data: &[u8]) -> GenericArray<u8, Self::L>;

    fn mix_hash(hash: GenericArray<u8, Self::L>, data: &[u8]) -> GenericArray<u8, Self::L>;

    fn mix_parts(hash: GenericArray<u8, Self::L>, parts: &[&[u8]]) -> GenericArray<u8, Self::L>;
}

impl<D> MixHash for D
where
    D: Update + BlockInput + FixedOutput + Default,
{
    type L = D::OutputSize;
    type B = D::BlockSize;

    fn init(data: &[u8]) -> GenericArray<u8, Self::L> {
        D::default().chain(data).finalize_fixed()
    }

    fn mix_hash(hash: GenericArray<u8, Self::L>, data: &[u8]) -> GenericArray<u8, Self::L> {
        D::default().chain(&hash).chain(data).finalize_fixed()
    }

    fn mix_parts(hash: GenericArray<u8, Self::L>, parts: &[&[u8]]) -> GenericArray<u8, Self::L> {
        let mut d = D::default().chain(&hash);
        let mut pos_in_buffer = 0;
        let mut buffer = GenericArray::<u8, Self::B>::default();
        for &part in parts {
            let new_pos = pos_in_buffer + part.len();
            if new_pos <= Self::B::USIZE {
                buffer[pos_in_buffer..new_pos].clone_from_slice(part);
                pos_in_buffer = new_pos;
            } else {
                let offset = Self::B::USIZE - pos_in_buffer;
                buffer[pos_in_buffer..].clone_from_slice(&part[..offset]);
                d.update(&buffer);

                pos_in_buffer = new_pos % Self::B::USIZE;
                if part.len() - pos_in_buffer - offset > 0 {
                    d.update(&part[offset..(part.len() - pos_in_buffer)]);
                }
                buffer[..pos_in_buffer].clone_from_slice(&part[(part.len() - pos_in_buffer)..]);
            }
        }
        d.chain(&buffer[..pos_in_buffer]).finalize_fixed()
    }
}

pub trait HkdfSplit<N>
where
    N: ArrayLength<GenericArray<u8, Self::L>>,
{
    type L: ArrayLength<u8>;

    fn hkdf_split(salt: Option<&[u8]>, ikm: &[u8]) -> GenericArray<GenericArray<u8, Self::L>, N>;
}

impl<D, N> HkdfSplit<N> for D
where
    D: Update + BlockInput + FixedOutput + Reset + Default + Clone,
    D::BlockSize: Clone,
    N: ArrayLength<GenericArray<u8, D::OutputSize>>,
    D::OutputSize: Mul<N>,
    <D::OutputSize as Mul<N>>::Output: ArrayLength<u8>,
{
    type L = D::OutputSize;

    fn hkdf_split(salt: Option<&[u8]>, ikm: &[u8]) -> GenericArray<GenericArray<u8, Self::L>, N> {
        use hkdf::Hkdf;

        let (_, hkdf) = Hkdf::<Self>::extract(salt, ikm);
        let mut okm: GenericArray<u8, <Self::L as Mul<N>>::Output> = GenericArray::default();
        hkdf.expand(&[], okm.as_mut()).unwrap();
        let l = <Self::L as Unsigned>::USIZE;
        GenericArray::generate(|i| {
            let mut s = GenericArray::default();
            s.as_mut_slice()
                .clone_from_slice(&okm[(l * i)..(l * (i + 1))]);
            s
        })
    }
}

pub trait HkdfSplitExt<A>
where
    A: NewAead,
{
    type L: ArrayLength<u8>;

    fn split_final(
        chaining_key: &[u8],
        data: &[u8],
    ) -> (GenericArray<u8, A::KeySize>, GenericArray<u8, A::KeySize>);

    fn split_2(
        chaining_key: &[u8],
        data: &[u8],
    ) -> (GenericArray<u8, Self::L>, GenericArray<u8, A::KeySize>);

    fn split_3(
        chaining_key: &[u8],
        data: &[u8],
    ) -> (
        GenericArray<u8, Self::L>,
        GenericArray<u8, A::KeySize>,
        GenericArray<u8, A::KeySize>,
    );
}

fn truncate<A>(chaining_key: &[u8]) -> GenericArray<u8, A::KeySize>
where
    A: NewAead,
{
    let input_length = chaining_key.len();
    let output_length = A::KeySize::USIZE;
    assert!(output_length <= input_length);

    let mut a = GenericArray::default();
    a[..output_length].clone_from_slice(&chaining_key[..output_length]);
    a
}

impl<A, T> HkdfSplitExt<A> for T
where
    A: NewAead,
    T: HkdfSplit<typenum::U2> + HkdfSplit<typenum::U3, L = <Self as HkdfSplit<typenum::U2>>::L>,
{
    type L = <T as HkdfSplit<typenum::U2>>::L;

    fn split_final(
        chaining_key: &[u8],
        data: &[u8],
    ) -> (GenericArray<u8, A::KeySize>, GenericArray<u8, A::KeySize>) {
        let keys = Self::hkdf_split(Some(chaining_key), data);
        let [send_key, receive_key]: [_; 2] = keys.into();
        (
            truncate::<A>(send_key.as_ref()),
            truncate::<A>(receive_key.as_ref()),
        )
    }

    fn split_2(
        chaining_key: &[u8],
        data: &[u8],
    ) -> (GenericArray<u8, Self::L>, GenericArray<u8, A::KeySize>) {
        let keys = Self::hkdf_split(Some(chaining_key), data);
        let [chaining_key, key]: [_; 2] = keys.into();
        (chaining_key, truncate::<A>(key.as_ref()))
    }

    fn split_3(
        chaining_key: &[u8],
        data: &[u8],
    ) -> (
        GenericArray<u8, Self::L>,
        GenericArray<u8, A::KeySize>,
        GenericArray<u8, A::KeySize>,
    ) {
        let keys = Self::hkdf_split(Some(chaining_key), data);
        let [chaining_key, middle, key]: [_; 3] = keys.into();
        (
            chaining_key,
            truncate::<A>(middle.as_ref()),
            truncate::<A>(key.as_ref()),
        )
    }
}
