use cryptography::aead::{NewAead, AeadInPlace};
use generic_array::GenericArray;
use byteorder::ByteOrder;
use core::{marker::PhantomData, fmt};
use super::{config::Config, hash::MixHash};

pub type Tag<C> = GenericArray<u8, <<C as Config>::Aead as AeadInPlace>::TagSize>;
pub type Aead<C> = GenericArray<u8, <<C as Config>::Aead as NewAead>::KeySize>;
pub type ChainingKey<C> = GenericArray<u8, <<C as Config>::MixHash as MixHash>::L>;

pub trait Rotor<C>
where
    C: Config,
{
    const INTERVAL: u64;

    fn new(chaining_key: ChainingKey<C>, key: Aead<C>) -> Self;

    fn rotate(&mut self, key: &mut C::Aead);
}

impl<C> Rotor<C> for PhantomData<C>
where
    C: Config,
{
    const INTERVAL: u64 = u64::MAX;

    fn new(chaining_key: ChainingKey<C>, key: Aead<C>) -> Self {
        let _ = (chaining_key, key);
        PhantomData
    }

    fn rotate(&mut self, key: &mut C::Aead) {
        let _ = key;
    }
}

#[derive(Clone)]
pub struct Unidirectional<C, R>
where
    C: Config,
    R: Rotor<C>,
{
    key: C::Aead,
    nonce: u64,
    rotor: R,
}

impl<C, R> Unidirectional<C, R>
where
    C: Config,
    R: Rotor<C>,
{
    fn new(chaining_key: ChainingKey<C>, key: Aead<C>) -> Self {
        Unidirectional {
            key: C::Aead::new(&key),
            nonce: 0,
            rotor: R::new(chaining_key, key),
        }
    }

    fn next(&mut self) {
        self.nonce += 1;
        if self.nonce % R::INTERVAL == 0 {
            self.rotor.rotate(&mut self.key);
        }
    }

    pub fn encrypt(&mut self, associated_data: &[u8], buffer: &mut [u8]) -> Tag<C> {
        let mut nonce_array = GenericArray::default();
        C::ByteOrder::write_u64(&mut nonce_array[4..], self.nonce);
        self.key
            .encrypt_in_place_detached(&nonce_array, associated_data, buffer)
            .map(|tag| {
                self.next();
                tag
            })
            .unwrap()
    }

    pub fn decrypt(
        &mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<C>,
    ) -> Result<(), ()> {
        let mut nonce_array = GenericArray::default();
        C::ByteOrder::write_u64(&mut nonce_array[4..], self.nonce);
        self.key
            .decrypt_in_place_detached(&nonce_array, associated_data, buffer, tag)
            .map(|()| {
                self.next();
            })
            .map_err(|_| ())
    }
}

impl<C, R> fmt::Debug for Unidirectional<C, R>
where
    C: Config,
    C::Aead: fmt::Debug,
    R: Rotor<C> + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Unidirectional")
            .field("nonce", &self.nonce)
            .field("key", &self.key)
            .field("rotor", &self.rotor)
            .finish()
    }
}

#[derive(Clone)]
pub struct Cipher<C, R>
where
    C: Config,
    R: Rotor<C>,
{
    pub send: Unidirectional<C, R>,
    pub receive: Unidirectional<C, R>,
}

impl<C, R> Cipher<C, R>
where
    C: Config,
    R: Rotor<C>,
{
    pub(crate) fn new(
        chaining_key: ChainingKey<C>,
        send_key: Aead<C>,
        receive_key: Aead<C>,
    ) -> Self {
        Cipher {
            send: Unidirectional::new(chaining_key.clone(), send_key),
            receive: Unidirectional::new(chaining_key, receive_key),
        }
    }

    pub fn swap(self) -> Self {
        Cipher {
            send: self.receive,
            receive: self.send,
        }
    }

    pub fn encrypt(&mut self, associated_data: &[u8], buffer: &mut [u8]) -> Tag<C> {
        self.send.encrypt(associated_data, buffer)
    }

    pub fn decrypt(
        &mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<C>,
    ) -> Result<(), ()> {
        self.receive.decrypt(associated_data, buffer, tag)
    }

    #[cfg(feature = "std")]
    pub fn encrypt_ext(&mut self, associated_data: &[u8], data: &mut Vec<u8>) {
        let tag = self.encrypt(associated_data, data.as_mut());
        data.extend_from_slice(tag.as_ref());
    }

    #[cfg(feature = "std")]
    pub fn decrypt_ext(&mut self, associated_data: &[u8], buffer: &mut Vec<u8>) -> Result<(), ()> {
        use generic_array::typenum::Unsigned;

        let mut tag = GenericArray::default();
        let pos = buffer.len() - <<C::Aead as AeadInPlace>::TagSize as Unsigned>::USIZE;
        tag.clone_from_slice(&buffer[pos..]);
        buffer.resize(pos, 0);
        self.decrypt(associated_data, buffer.as_mut(), &tag)
    }
}

impl<C, R> fmt::Debug for Cipher<C, R>
where
    C: Config,
    C::Aead: fmt::Debug,
    R: Rotor<C> + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cipher")
            .field("send", &self.send)
            .field("receive", &self.receive)
            .finish()
    }
}
