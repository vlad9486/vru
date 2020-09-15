use generic_array::{
    GenericArray,
    typenum::{self, Unsigned},
};
use aead::{NewAead, AeadInPlace};
use byteorder::ByteOrder;
use core::{fmt, marker::PhantomData, ops::Add};
use super::{
    config::Config,
    hash::{MixHash, HkdfSplitExt},
    cipher_state::{ChainingKey, Tag, Cipher, Rotor},
};

pub struct Key<C, N>
where
    C: Config,
    N: Unsigned,
{
    chaining_key: ChainingKey<C>,
    aead: C::Aead,
    nonce: PhantomData<N>,
}

impl<C, N> Into<ChainingKey<C>> for Key<C, N>
where
    C: Config,
    N: Unsigned,
{
    fn into(self) -> ChainingKey<C> {
        self.chaining_key
    }
}

impl<C, N> Key<C, N>
where
    C: Config,
    N: Unsigned + Add<typenum::U1>,
    <N as Add<typenum::U1>>::Output: Unsigned,
{
    fn increase(self) -> Key<C, <N as Add<typenum::U1>>::Output> {
        match self {
            Key {
                chaining_key: chaining_key,
                aead: aead,
                nonce: _,
            } => Key {
                chaining_key: chaining_key,
                aead: aead,
                nonce: PhantomData,
            },
        }
    }
}

pub struct Authenticated<C, T>
where
    C: Config,
{
    tag: Tag<C>,
    data: T,
}

impl<C, T> Authenticated<C, T>
where
    C: Config,
{
    pub fn destruct<F>(self, mut f: F) -> T
    where
        F: FnMut(Tag<C>),
    {
        f(self.tag);
        self.data
    }
}

#[derive(Clone)]
pub struct SymmetricState<C, K>
where
    C: Config,
{
    key: K,
    hash: GenericArray<u8, <C::MixHash as MixHash>::L>,
}

impl<C> SymmetricState<C, ChainingKey<C>>
where
    C: Config,
{
    pub fn new(name: &str) -> Self {
        let length = name.as_bytes().len();
        let size = <C::MixHash as MixHash>::L::USIZE;
        let hash = if length <= size {
            let mut array = GenericArray::default();
            array[0..length].copy_from_slice(name.as_bytes());
            array
        } else {
            C::MixHash::init(&name.as_bytes())
        };

        SymmetricState {
            key: hash.clone(),
            hash: hash,
        }
    }
}

impl<C, K> SymmetricState<C, K>
where
    C: Config,
{
    pub fn hash(&self) -> GenericArray<u8, <C::MixHash as MixHash>::L> {
        self.hash.clone()
    }

    pub fn mix_hash(self, data: &[u8]) -> Self {
        match self {
            SymmetricState {
                key: key,
                hash: hash,
            } => SymmetricState {
                key: key,
                hash: C::MixHash::mix_hash(hash, data),
            },
        }
    }
}

impl<C, K> SymmetricState<C, K>
where
    C: Config,
    K: Into<ChainingKey<C>>,
{
    pub fn mix_shared_secret(self, data: &[u8]) -> SymmetricState<C, Key<C, typenum::U0>> {
        match self {
            SymmetricState {
                key: key,
                hash: hash,
            } => {
                let c = key.into();
                let (c, a) = C::HkdfSplit::split_2(c.as_ref(), data);
                SymmetricState {
                    key: Key {
                        chaining_key: c,
                        aead: C::Aead::new(&a),
                        nonce: PhantomData,
                    },
                    hash: hash,
                }
            },
        }
    }

    pub fn mix_psk(self, data: &[u8]) -> SymmetricState<C, Key<C, typenum::U0>> {
        match self {
            SymmetricState {
                key: key,
                hash: hash,
            } => {
                let c = key.into();
                let (c, m, a) = C::HkdfSplit::split_3(c.as_ref(), data);
                SymmetricState {
                    key: Key {
                        chaining_key: c,
                        aead: C::Aead::new(&a),
                        nonce: PhantomData,
                    },
                    hash: C::MixHash::mix_hash(hash, m.as_ref()),
                }
            },
        }
    }

    pub fn finish<R>(self) -> Cipher<C, R>
    where
        R: Rotor<C>,
    {
        let c = self.key.into();
        let (_0, _1) = C::HkdfSplit::split_final(c.as_ref(), &[]);
        Cipher::new(c, _0, _1)
    }
}

impl<C, N> SymmetricState<C, Key<C, N>>
where
    C: Config,
    N: Unsigned + Add<typenum::U1>,
    <N as Add<typenum::U1>>::Output: Unsigned,
{
    pub fn encrypt(
        self,
        data: &mut [u8],
    ) -> Authenticated<C, SymmetricState<C, Key<C, <N as Add<typenum::U1>>::Output>>> {
        let mut nonce = GenericArray::default();
        C::ByteOrder::write_u64(&mut nonce[4..], N::U64);
        let tag = self
            .key
            .aead
            .encrypt_in_place_detached(&nonce, &self.hash, data)
            .unwrap();
        Authenticated {
            tag: tag.clone(),
            data: SymmetricState {
                key: self.key.increase(),
                hash: C::MixHash::mix_parts(self.hash, &[data, tag.as_ref()]),
            },
        }
    }

    pub fn decrypt(
        self,
        data: &mut [u8],
        tag: Tag<C>,
    ) -> Result<SymmetricState<C, Key<C, <N as Add<typenum::U1>>::Output>>, ()> {
        let mut nonce = GenericArray::default();
        C::ByteOrder::write_u64(&mut nonce[4..], N::U64);
        let hash = C::MixHash::mix_parts(self.hash.clone(), &[data, tag.as_ref()]);
        self.key
            .aead
            .decrypt_in_place_detached(&nonce, &hash, data, &tag)
            .map(|()| SymmetricState {
                key: self.key.increase(),
                hash: hash,
            })
            .map_err(|_| ())
    }
}

impl<C, K> fmt::Debug for SymmetricState<C, K>
where
    C: Config,
    K: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymmetricState")
            .field("key", &self.key)
            .field("hash", &hex::encode(&self.hash))
            .finish()
    }
}
