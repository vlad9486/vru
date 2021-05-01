use std::ops::Add;
use vru_noise::{SymmetricState, Config, Key};
use rac::{
    Line, Concat,
    generic_array::typenum::{self, Unsigned},
};
use super::super::Encrypted;

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
        let (state, tag) = self.encrypt(&mut data);
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
