use crate::{
    state::{NoiseAlgorithm, EncryptedPayload, State, StateError, CompressedCurve},
};
use super::EmptyLine;

use core::marker::PhantomData;
use rac::{LineValid, Curve};
use generic_array::{
    GenericArray,
    typenum::{Unsigned, Bit},
};

/// the interface of the handshake operation
pub trait Token<A>
where
    A: NoiseAlgorithm,
{
    type Input: LineValid;
    type Output: LineValid;

    const HAS_PAYLOAD: bool;

    fn take(input: Self::Input, state: State<A>) -> Result<(State<A>, Self::Output), StateError>;

    fn give(state: State<A>, output: Self::Output) -> (State<A>, Self::Input);
}

pub struct Payload<A, P>(PhantomData<(A, P)>)
where
    A: NoiseAlgorithm,
    P: LineValid;

impl<A, P> Token<A> for Payload<A, P>
where
    A: NoiseAlgorithm,
    P: LineValid,
    EncryptedPayload<A, P>: LineValid,
{
    type Input = EncryptedPayload<A, P>;
    type Output = P;

    const HAS_PAYLOAD: bool = true;

    fn take(input: Self::Input, state: State<A>) -> Result<(State<A>, Self::Output), StateError> {
        let mut state = state;

        let output = state.decrypt(input)?;
        Ok((state, output))
    }

    fn give(state: State<A>, output: Self::Output) -> (State<A>, Self::Input) {
        let mut state = state;

        let input = state.encrypt(&output);
        (state, input)
    }
}

pub struct EncryptedPoint<A, I>(PhantomData<(A, I)>)
where
    A: NoiseAlgorithm,
    I: Unsigned;

impl<A, I> Token<A> for EncryptedPoint<A, I>
where
    A: NoiseAlgorithm,
    I: Unsigned,
    EncryptedPayload<A, CompressedCurve<A::Curve>>: LineValid,
{
    type Input = EncryptedPayload<A, CompressedCurve<A::Curve>>;
    type Output = EmptyLine;

    const HAS_PAYLOAD: bool = false;

    fn take(input: Self::Input, state: State<A>) -> Result<(State<A>, Self::Output), StateError> {
        let (mut state, compressed) = Payload::take(input, state)?;
        state.store_compressed::<I>(&compressed)?;
        Ok((state, EmptyLine::default()))
    }

    fn give(state: State<A>, output: Self::Output) -> (State<A>, Self::Input) {
        let _ = output;
        let output = state.compressed::<I>();
        Payload::give(state, output)
    }
}

pub struct Point<A, I, B>(PhantomData<(A, I, B)>)
where
    A: NoiseAlgorithm,
    I: Unsigned,
    B: Bit;

impl<A, I, B> Token<A> for Point<A, I, B>
where
    A: NoiseAlgorithm,
    I: Unsigned,
    B: Bit,
{
    type Input = GenericArray<u8, <A::Curve as Curve>::CompressedLength>;
    type Output = EmptyLine;

    const HAS_PAYLOAD: bool = false;

    fn take(input: Self::Input, state: State<A>) -> Result<(State<A>, Self::Output), StateError> {
        let mut state = state;

        state.store_compressed::<I>(&input)?;
        state.mix_hash::<I, B>();
        Ok((state, EmptyLine::default()))
    }

    fn give(state: State<A>, output: Self::Output) -> (State<A>, Self::Input) {
        let mut state = state;

        let _ = output;
        state.mix_hash::<I, B>();
        let input = state.compressed::<I>();
        (state, input)
    }
}

pub struct MixDh<A, I, J>(PhantomData<(A, I, J)>)
where
    A: NoiseAlgorithm,
    I: Unsigned,
    J: Unsigned;

impl<A, I, J> Token<A> for MixDh<A, I, J>
where
    A: NoiseAlgorithm,
    I: Unsigned,
    J: Unsigned,
{
    type Input = EmptyLine;
    type Output = EmptyLine;

    const HAS_PAYLOAD: bool = false;

    fn take(input: Self::Input, state: State<A>) -> Result<(State<A>, Self::Output), StateError> {
        let mut state = state;

        let _ = input;
        state.mix_key::<I, J>();
        Ok((state, EmptyLine::default()))
    }

    fn give(state: State<A>, output: Self::Output) -> (State<A>, Self::Input) {
        let mut state = state;

        let _ = output;
        state.mix_key::<I, J>();
        (state, EmptyLine::default())
    }
}

pub struct MixPsk<A>(PhantomData<A>)
where
    A: NoiseAlgorithm;

impl<A> Token<A> for MixPsk<A>
where
    A: NoiseAlgorithm,
{
    type Input = EmptyLine;
    type Output = EmptyLine;

    const HAS_PAYLOAD: bool = false;

    fn take(input: Self::Input, state: State<A>) -> Result<(State<A>, Self::Output), StateError> {
        let mut state = state;

        let _ = input;
        state.mix_psk();
        Ok((state, EmptyLine::default()))
    }

    fn give(state: State<A>, output: Self::Output) -> (State<A>, Self::Input) {
        let mut state = state;

        let _ = output;
        state.mix_psk();
        (state, EmptyLine::default())
    }
}
