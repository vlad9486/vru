use std::{ops::Add, marker::PhantomData};
use vru_noise::{Cipher, Unidirectional, Tag, SymmetricState, Config, Key};
use rac::{
    Array, LineValid, Line, Concat,
    generic_array::typenum::{self, Unsigned},
};

pub type Noise = (
    sha2::Sha256,
    byteorder::LittleEndian,
    chacha20poly1305::ChaCha20Poly1305,
);

type TrivialRotor = PhantomData<Noise>;

pub type TrivialCipher = Cipher<Noise, TrivialRotor>;

pub type TrivialUnidirectional = Unidirectional<Noise, TrivialRotor>;

pub type Encrypted<C, L> = Concat<Array<<L as LineValid>::Length>, Tag<C>>;

pub trait SymmetricStateOps<C>
where
    C: Config,
{
    type NextState;

    fn encrypt_line<L>(self, data: L) -> (Self::NextState, Encrypted<C, L>)
    where
        L: Line,
        Encrypted<C, L>: Line;

    fn decrypt_line<L>(self, encrypted: Encrypted<C, L>) -> Result<(Self::NextState, L), ()>
    where
        L: Line,
        Encrypted<C, L>: Line;
}

impl<C, N> SymmetricStateOps<C> for SymmetricState<C, Key<C, N>>
where
    C: Config,
    N: Unsigned + Add<typenum::U1>,
    <N as Add<typenum::U1>>::Output: Unsigned,
{
    type NextState = SymmetricState<C, Key<C, <N as Add<typenum::U1>>::Output>>;

    fn encrypt_line<L>(self, data: L) -> (Self::NextState, Encrypted<C, L>)
    where
        L: Line,
        Encrypted<C, L>: Line,
    {
        let mut data = data.clone_line();
        let mut tag = Array::default();
        let state = self.encrypt(&mut data).destruct(|t| tag = t);
        (state, Concat(data, tag))
    }

    fn decrypt_line<L>(self, encrypted: Encrypted<C, L>) -> Result<(Self::NextState, L), ()>
    where
        L: Line,
        Encrypted<C, L>: Line,
    {
        let Concat(mut data, tag) = encrypted;
        let state = self.decrypt(&mut data, tag)?;
        Ok((state, L::clone_array(&data)))
    }
}