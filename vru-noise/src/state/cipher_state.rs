use super::{
    noise_nonce::NoiseNonce,
    traits::{CipherAlgorithm, Rotor, Tag, AeadKey, ChainingKey},
};

use aead::{NewAead, AeadInPlace};
use generic_array::GenericArray;
use zeroize::Zeroize;

pub struct CipherState<A, R>
where
    A: CipherAlgorithm,
    R: Rotor<A>,
{
    chaining_key: ChainingKey<A>,
    key: A::Aead,
    nonce: u64,
    encrypted: u64,
    decrypted: u64,
    rotor: R,
}

impl<A, R> Zeroize for CipherState<A, R>
where
    A: CipherAlgorithm,
    R: Rotor<A>,
{
    fn zeroize(&mut self) {
        self.chaining_key.as_mut_slice().zeroize();
        self.nonce.zeroize();
    }
}

impl<A, R> CipherState<A, R>
where
    A: CipherAlgorithm,
    R: Rotor<A>,
{
    pub fn new(chaining_key: &ChainingKey<A>) -> Self {
        Self::reset(chaining_key.clone(), &GenericArray::default())
    }

    fn reset<Nr>(chaining_key: ChainingKey<A>, key: &AeadKey<A>) -> CipherState<A, Nr>
    where
        Nr: Rotor<A>,
    {
        let rotor = Nr::new(&key);
        CipherState {
            chaining_key: chaining_key,
            key: A::Aead::new(&key),
            nonce: 0,
            encrypted: 0,
            decrypted: 0,
            rotor: rotor,
        }
    }

    fn reset_preserve_counters(&mut self, chaining_key: ChainingKey<A>, key: AeadKey<A>) {
        self.chaining_key = chaining_key;
        self.key = A::Aead::new(&key);
        self.nonce = 0;
    }

    pub fn encrypt(&mut self, associated_data: &[u8], buffer: &mut [u8]) -> Tag<A> {
        use byteorder::ByteOrder;

        let mut nonce = GenericArray::default();
        <<A::Aead as NoiseNonce>::Endianness as ByteOrder>::write_u64(&mut nonce[4..], self.nonce);
        let tag = self
            .key
            .encrypt_in_place_detached(&nonce, associated_data, buffer)
            .unwrap();
        self.encrypted += buffer.as_ref().len() as u64;
        self.next();
        tag
    }

    pub fn decrypt(
        &mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<A>,
    ) -> Result<(), ()> {
        use byteorder::ByteOrder;

        let mut nonce = GenericArray::default();
        <<A::Aead as NoiseNonce>::Endianness as ByteOrder>::write_u64(&mut nonce[4..], self.nonce);
        self.key
            .decrypt_in_place_detached(&nonce, associated_data, buffer, tag)
            .map(|()| {
                self.decrypted += buffer.as_ref().len() as u64;
                self.next();
            })
            .map_err(|_| ())
    }

    fn next(&mut self) {
        self.nonce += 1;
        if self.nonce % R::INTERVAL == 0 {
            self.rotor.rotate(&mut self.chaining_key, &mut self.key);
        }
    }

    pub fn mix<T>(&mut self, data: &T)
    where
        T: AsRef<[u8]>,
    {
        let (chaining_key, key) = A::split_2(&self.chaining_key, data);
        self.reset_preserve_counters(chaining_key, key);
    }

    pub fn mix_psk<T>(&mut self, data: &T) -> AeadKey<A>
    where
        T: AsRef<[u8]>,
    {
        let (chaining_key, hash, key) = A::split_3(&self.chaining_key, data);
        self.reset_preserve_counters(chaining_key, key);
        hash
    }

    pub fn split<Nr>(self, swap: bool) -> CipherPair<A, Nr>
    where
        Nr: Rotor<A>,
    {
        use generic_array::typenum::U0;

        let e = GenericArray::<u8, U0>::default();
        let (send, receive) = A::split_2(&self.chaining_key, &e);
        let send = A::truncate(&send);

        let (send, receive) = if swap {
            (receive, send)
        } else {
            (send, receive)
        };

        CipherPair {
            send: Self::reset(self.chaining_key.clone(), &send),
            receive: Self::reset(self.chaining_key, &receive),
        }
    }
}

#[derive(Debug)]
pub struct CipherError;

pub struct CipherPair<A, R>
where
    A: CipherAlgorithm,
    R: Rotor<A>,
{
    send: CipherState<A, R>,
    receive: CipherState<A, R>,
}

impl<A, R> Zeroize for CipherPair<A, R>
where
    A: CipherAlgorithm,
    R: Rotor<A>,
{
    fn zeroize(&mut self) {
        self.send.zeroize();
        self.receive.zeroize();
    }
}

impl<A, R> CipherPair<A, R>
where
    A: CipherAlgorithm,
    R: Rotor<A>,
{
    pub fn encrypt(&mut self, associated_data: &[u8], buffer: &mut [u8]) -> Tag<A> {
        self.send.encrypt(associated_data, buffer)
    }

    pub fn decrypt(
        &mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<A>,
    ) -> Result<(), CipherError> {
        self.receive
            .decrypt(associated_data, buffer, tag)
            .map_err(|()| CipherError)
    }

    pub fn encrypted_bytes(&self) -> u64 {
        self.send.encrypted.clone()
    }

    pub fn encrypted_messages(&self) -> u64 {
        self.send.nonce.clone()
    }

    pub fn decrypted_bytes(&self) -> u64 {
        self.receive.decrypted.clone()
    }

    pub fn decrypted_messages(&self) -> u64 {
        self.receive.nonce.clone()
    }
}

#[cfg(test)]
impl<A, R> CipherPair<A, R>
where
    CipherState<A, R>: Eq,
    R: Rotor<A>,
    A: CipherAlgorithm,
{
    pub fn is_match(&self, other: &Self) -> bool {
        self.send == other.receive && self.receive == other.send
    }
}

mod implementations {
    use super::{CipherAlgorithm, CipherState, CipherError, Rotor};

    use core::fmt;

    impl<A, R> fmt::Debug for CipherState<A, R>
    where
        A: CipherAlgorithm,
        R: Rotor<A>,
        A::Aead: fmt::Debug,
    {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("CipherState")
                .field("chaining_key", &self.chaining_key)
                .field("key", &self.key)
                .field("nonce", &self.nonce)
                .finish()
        }
    }

    impl<A, R> PartialEq for CipherState<A, R>
    where
        A: CipherAlgorithm,
        R: Rotor<A>,
        A::Aead: Eq,
    {
        fn eq(&self, other: &Self) -> bool {
            self.chaining_key == other.chaining_key
                && self.key == other.key
                && self.nonce == other.nonce
        }
    }

    impl<A, R> Eq for CipherState<A, R>
    where
        A: CipherAlgorithm,
        R: Rotor<A>,
        A::Aead: Eq,
    {
    }

    impl<A, R> Clone for CipherState<A, R>
    where
        A: CipherAlgorithm,
        R: Rotor<A> + Clone,
    {
        fn clone(&self) -> Self {
            CipherState {
                chaining_key: self.chaining_key.clone(),
                key: self.key.clone(),
                nonce: self.nonce.clone(),
                encrypted: self.encrypted.clone(),
                decrypted: self.decrypted.clone(),
                rotor: self.rotor.clone(),
            }
        }
    }

    impl fmt::Display for CipherError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{:?}", self)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for CipherError {}
}
