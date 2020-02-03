use crate::{
    state::{NoiseAlgorithm, State, StateError},
};
use super::{EmptyLine, token::Token};

use core::marker::PhantomData;
use rac::{LineValid, Concat};

#[derive(Debug, Eq, PartialEq)]
pub struct PatternError {
    pub level: usize,
    pub error: StateError,
}

impl PatternError {
    pub fn level(level: usize) -> impl FnOnce(StateError) -> Self {
        move |error| PatternError { level, error }
    }
}

pub trait Pattern<A>
where
    Self: Sized,
    A: NoiseAlgorithm,
{
    type Input: LineValid;
    type Output: LineValid;

    const DEEPNESS: usize;
    const HAS_PAYLOAD: bool;

    fn take(
        input: Self::Input,
        pattern: State<A>,
    ) -> Result<(State<A>, Self::Output), PatternError>;

    fn give(pattern: State<A>, output: Self::Output) -> (State<A>, Self::Input);
}

pub struct BasePattern<A>(PhantomData<A>)
where
    A: NoiseAlgorithm;

// base
impl<A> Pattern<A> for BasePattern<A>
where
    A: NoiseAlgorithm,
{
    type Input = EmptyLine;
    type Output = EmptyLine;

    const DEEPNESS: usize = 0;

    const HAS_PAYLOAD: bool = false;

    fn take(input: Self::Input, state: State<A>) -> Result<(State<A>, Self::Output), PatternError> {
        let _ = input;
        Ok((state, EmptyLine::default()))
    }

    fn give(state: State<A>, output: Self::Output) -> (State<A>, Self::Input) {
        let _ = output;
        (state, EmptyLine::default())
    }
}

// step
impl<A, E, M> Pattern<A> for (E, M)
where
    A: NoiseAlgorithm,
    E: Pattern<A>,
    M: Token<A>,
    Concat<E::Input, M::Input>: LineValid,
    Concat<E::Output, M::Output>: LineValid,
{
    type Input = Concat<E::Input, M::Input>;
    type Output = Concat<E::Output, M::Output>;

    const DEEPNESS: usize = E::DEEPNESS + 1;

    const HAS_PAYLOAD: bool = E::HAS_PAYLOAD || M::HAS_PAYLOAD;

    fn take(input: Self::Input, state: State<A>) -> Result<(State<A>, Self::Output), PatternError> {
        let Concat(evolution_input, modifier_input) = input;
        let (state, evolution_output) = E::take(evolution_input, state)?;
        let (state, modifier_output) =
            M::take(modifier_input, state).map_err(PatternError::level(E::DEEPNESS))?;
        Ok((state, Concat(evolution_output, modifier_output)))
    }

    fn give(state: State<A>, output: Self::Output) -> (State<A>, Self::Input) {
        let Concat(evolution_output, modifier_output) = output;
        let (state, evolution_input) = E::give(state, evolution_output);
        let (state, modifier_input) = M::give(state, modifier_output);
        (state, Concat(evolution_input, modifier_input))
    }
}
