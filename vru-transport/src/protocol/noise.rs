use std::marker::PhantomData;
use vru_noise::{Cipher, Unidirectional, Tag};
use rac::{Array, LineValid, Concat};

pub type Noise = (
    sha2::Sha256,
    byteorder::LittleEndian,
    chacha20poly1305::ChaCha20Poly1305,
);

type TrivialRotor = PhantomData<Noise>;

pub type TrivialCipher = Cipher<Noise, TrivialRotor>;

pub type TrivialUnidirectional = Unidirectional<Noise, TrivialRotor>;

pub type Encrypted<C, L> = Concat<Array<<L as LineValid>::Length>, Tag<C>>;
