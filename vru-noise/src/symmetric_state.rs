use aead::{NewAead, AeadInPlace};
use generic_array::{
    GenericArray,
    typenum::{self, Unsigned},
};
use byteorder::ByteOrder;
use core::{fmt, marker::PhantomData, ops::Add};
use super::{
    config::Config,
    hash::{MixHash, HkdfSplitExt},
    cipher_state::{MacMismatch, ChainingKey, Tag, Cipher, Rotor},
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

impl<C, N> From<Key<C, N>> for ChainingKey<C>
where
    C: Config,
    N: Unsigned,
{
    fn from(v: Key<C, N>) -> Self {
        v.chaining_key
    }
}

impl<C, N> Key<C, N>
where
    C: Config,
    N: Unsigned + Add<typenum::U1>,
    <N as Add<typenum::U1>>::Output: Unsigned,
{
    fn increase(self) -> Key<C, <N as Add<typenum::U1>>::Output> {
        let Key {
            chaining_key, aead, ..
        } = self;
        Key {
            chaining_key,
            aead,
            nonce: PhantomData,
        }
    }
}

pub type SymmetricStateNext<C, N> = SymmetricState<C, Key<C, <N as Add<typenum::U1>>::Output>>;

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
            hash,
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
        let SymmetricState { key, hash } = self;
        let hash = C::MixHash::mix_hash(hash, data);
        SymmetricState { key, hash }
    }
}

impl<C, K> SymmetricState<C, K>
where
    C: Config,
    K: Into<ChainingKey<C>>,
{
    pub fn mix_shared_secret(self, data: &[u8]) -> SymmetricState<C, Key<C, typenum::U0>> {
        let SymmetricState { key, hash } = self;

        let chaining_key = key.into();
        let (chaining_key, aead) = C::HkdfSplit::split_2(chaining_key.as_ref(), data);
        let aead = C::Aead::new(&aead);
        let key = Key {
            chaining_key,
            aead,
            nonce: PhantomData,
        };
        SymmetricState { key, hash }
    }

    pub fn mix_psk(self, data: &[u8]) -> SymmetricState<C, Key<C, typenum::U0>> {
        let SymmetricState { key, hash } = self;

        let chaining_key = key.into();
        let (chaining_key, middle, aead) = C::HkdfSplit::split_3(chaining_key.as_ref(), data);
        let aead = C::Aead::new(&aead);
        let key = Key {
            chaining_key,
            aead,
            nonce: PhantomData,
        };
        let hash = C::MixHash::mix_hash(hash, middle.as_ref());
        SymmetricState { key, hash }
    }

    pub fn finish<R>(self) -> (Cipher<C, R>, GenericArray<u8, <C::MixHash as MixHash>::L>)
    where
        R: Rotor<C>,
    {
        let c = self.key.into();
        let (send_key, receive_key) = C::HkdfSplit::split_final(c.as_ref(), &[]);
        (Cipher::new(c, send_key, receive_key), self.hash)
    }
}

impl<C, N> SymmetricState<C, Key<C, N>>
where
    C: Config,
    N: Unsigned + Add<typenum::U1>,
    <N as Add<typenum::U1>>::Output: Unsigned,
{
    pub fn encrypt(self, data: &mut [u8]) -> (SymmetricStateNext<C, N>, Tag<C>) {
        let mut nonce = GenericArray::default();
        C::ByteOrder::write_u64(&mut nonce[4..], N::U64);
        let tag = self
            .key
            .aead
            .encrypt_in_place_detached(&nonce, &self.hash, data)
            .unwrap();
        (
            SymmetricState {
                key: self.key.increase(),
                hash: C::MixHash::mix_parts(self.hash, &[data, tag.as_ref()]),
            },
            tag,
        )
    }

    #[cfg(feature = "std")]
    pub fn encrypt_ext(self, data: &mut Vec<u8>) -> SymmetricStateNext<C, N> {
        let (state, tag) = self.encrypt(data.as_mut());
        data.extend_from_slice(&tag);
        state
    }

    pub fn decrypt(
        self,
        data: &mut [u8],
        tag: Tag<C>,
    ) -> Result<SymmetricStateNext<C, N>, MacMismatch> {
        let mut nonce = GenericArray::default();
        C::ByteOrder::write_u64(&mut nonce[4..], N::U64);
        let hash = C::MixHash::mix_parts(self.hash.clone(), &[data, tag.as_ref()]);
        self.key
            .aead
            .decrypt_in_place_detached(&nonce, &self.hash, data, &tag)
            .map(|()| SymmetricState {
                key: self.key.increase(),
                hash,
            })
            .map_err(|_| MacMismatch)
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
