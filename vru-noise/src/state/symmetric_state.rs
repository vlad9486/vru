use super::traits::{NoiseAlgorithm, MixHash, HashLength, EncryptedPayload, Rotor, SimpleRotor};
use super::cipher_state::{CipherState, CipherPair};

use generic_array::GenericArray;
use rac::{LineValid, Concat, Curve};
use either::Either;
use zeroize::Zeroize;

pub struct SymmetricState<A>
where
    A: NoiseAlgorithm,
{
    key: CipherState<A::CipherAlgorithm, SimpleRotor<A::CipherAlgorithm>>,
    hash: GenericArray<u8, HashLength<A>>,
}

impl<A> SymmetricState<A>
where
    A: NoiseAlgorithm,
{
    pub fn new(name: &str) -> Self {
        use generic_array::typenum::marker_traits::Unsigned;

        let length = name.as_bytes().len();
        let size = HashLength::<A>::to_usize();
        let hash = if length <= size {
            let mut array = GenericArray::default();
            array[0..length].copy_from_slice(name.as_bytes());
            array
        } else {
            A::MixHash::init(&name.as_bytes())
        };

        let key = CipherState::new(&hash);
        SymmetricState {
            key: key,
            hash: hash,
        }
    }

    pub fn encrypt<T>(&mut self, plain: &T) -> EncryptedPayload<A, T>
    where
        T: LineValid,
        EncryptedPayload<A, T>: LineValid,
    {
        let mut encrypted = plain.clone_line();
        let tag = self.key.encrypt(&self.hash, &mut encrypted);
        let v = Concat(encrypted, tag);
        self.mix_hash(&v.clone_line());
        v
    }

    pub fn decrypt<T>(&mut self, encrypted: EncryptedPayload<A, T>) -> Result<T, Either<(), ()>>
    where
        T: LineValid,
        EncryptedPayload<A, T>: LineValid,
    {
        let mut plain_array = encrypted.as_ref_u().clone();
        self.key
            .decrypt(&self.hash, &mut plain_array, &encrypted.as_ref_v())
            .map_err(Either::Left)?;
        self.mix_hash(&encrypted.clone_line());
        T::try_clone_array(&plain_array).map_err(Either::Right)
    }

    pub fn mix_key(&mut self, public: &A::Curve, secret: &<A::Curve as Curve>::Scalar) {
        let dh = public.exp_ec(secret).compress();
        self.mix_key_single(&dh);
    }

    pub fn mix_key_single(
        &mut self,
        compressed_curve: &GenericArray<u8, <A::Curve as Curve>::CompressedLength>,
    ) {
        use generic_array::typenum::marker_traits::Bit;

        if !A::HashDh::to_bool() {
            self.key.mix(compressed_curve);
        } else {
            self.key.mix(&A::MixHash::init(compressed_curve));
        }
    }

    pub fn mix_hash<T>(&mut self, data: &T)
    where
        T: AsRef<[u8]>,
    {
        A::MixHash::mix_hash(&mut self.hash, data);
    }

    pub fn mix_psk<T>(&mut self, data: &T)
    where
        T: AsRef<[u8]>,
    {
        let hash = self.key.mix_psk(data);
        self.mix_hash(&hash.clone_line());
    }

    pub fn split<R>(self, swap: bool) -> CipherPair<A::CipherAlgorithm, R>
    where
        R: Rotor<A::CipherAlgorithm>,
    {
        let mut s = self;
        s.hash.as_mut_slice().zeroize();
        s.key.split(swap)
    }

    pub fn hash(&self) -> GenericArray<u8, HashLength<A>> {
        self.hash.clone()
    }
}

mod implementations {
    use super::{NoiseAlgorithm, SymmetricState, CipherState, SimpleRotor};

    use core::fmt;

    impl<A> fmt::Debug for SymmetricState<A>
    where
        A: NoiseAlgorithm,
        CipherState<A::CipherAlgorithm, SimpleRotor<A::CipherAlgorithm>>: fmt::Debug,
    {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.debug_struct("SymmetricState")
                .field("key", &self.key)
                .field("hash", &self.hash)
                .finish()
        }
    }

    impl<A> PartialEq for SymmetricState<A>
    where
        A: NoiseAlgorithm,
        CipherState<A::CipherAlgorithm, SimpleRotor<A::CipherAlgorithm>>: Eq,
    {
        fn eq(&self, other: &Self) -> bool {
            self.key == other.key && self.hash == other.hash
        }
    }

    impl<A> Eq for SymmetricState<A>
    where
        A: NoiseAlgorithm,
        CipherState<A::CipherAlgorithm, SimpleRotor<A::CipherAlgorithm>>: Eq,
    {
    }

    impl<A> Clone for SymmetricState<A>
    where
        A: NoiseAlgorithm,
    {
        fn clone(&self) -> Self {
            SymmetricState {
                key: self.key.clone(),
                hash: self.hash.clone(),
            }
        }
    }
}
