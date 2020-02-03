use crate::{
    state::{NoiseAlgorithm, State, CipherPair, AeadKey, HashLength, Rotor},
};
use super::{
    EmptyLine,
    pattern::{Pattern, PatternError},
};

use core::marker::PhantomData;
use generic_array::{GenericArray, typenum::Unsigned};
use rac::{LineValid, Concat, Curve};

#[cfg(feature = "std")]
use std::{io, future::Future};

#[cfg(feature = "std")]
use generic_array::ArrayLength;

#[cfg(feature = "std")]
#[derive(Debug)]
pub enum HandshakeError {
    BadPattern(PatternError),
    BadPayload(()),
    BadMessage(()),
    BadPreshare(()),
    IoErrorReadPayload(io::Error),
    IoErrorWritePayload(io::Error),
    IoErrorReadMessage(io::Error),
    IoErrorWriteMessage(io::Error),
}

pub struct HandshakeState<A, H>
where
    A: NoiseAlgorithm,
    H: History<A>,
{
    initial_state: State<A>,
    phantom_data: PhantomData<H>,
}

impl<A> HandshakeState<A, BaseHistory<A>>
where
    A: NoiseAlgorithm,
{
    pub fn new(name: &str, prologue: &[u8]) -> Self {
        HandshakeState {
            initial_state: State::new(name, prologue),
            phantom_data: PhantomData,
        }
    }

    pub fn with_point<I>(self, point: A::Curve) -> Self
    where
        I: Unsigned,
    {
        Self::from_inner(self.initial_state.with_point::<I>(point))
    }

    pub fn with_secret<I>(self, secret: <A::Curve as Curve>::Scalar) -> Self
    where
        I: Unsigned,
    {
        Self::from_inner(self.initial_state.with_secret::<I>(secret))
    }

    pub fn with_psk(self, psk: AeadKey<A::CipherAlgorithm>) -> Self {
        Self::from_inner(self.initial_state.with_psk(psk))
    }

    #[cfg(feature = "std")]
    pub async fn handshake<H, Io, MaxMessage, MaxPayload, Rfn, R, Wfn, W, Pfn, P, Qfn, Q, T>(
        self,
        initiator: bool,
        io: Io,
        read_fn: &mut Rfn,
        write_fn: &mut Wfn,
        payload_read_fn: &mut Pfn,
        payload_write_fn: &mut Qfn,
    ) -> Result<(CipherPair<A::CipherAlgorithm, T>, Io), HandshakeError>
    where
        A: NoiseAlgorithm,
        H: History<A>,
        Rfn: FnMut(Io, usize) -> R,
        R: Future<Output = Result<(GenericArray<u8, MaxMessage>, Io), io::Error>>,
        Wfn: FnMut(Io, usize, GenericArray<u8, MaxMessage>) -> W,
        W: Future<Output = Result<Io, io::Error>>,
        Pfn: FnMut(usize) -> P,
        P: Future<Output = Result<GenericArray<u8, MaxPayload>, io::Error>>,
        Qfn: FnMut(usize, GenericArray<u8, MaxPayload>) -> Q,
        Q: Future<Output = Result<(), io::Error>>,
        MaxMessage: ArrayLength<u8>,
        MaxPayload: ArrayLength<u8>,
        T: Rotor<A::CipherAlgorithm>,
    {
        use self::HandshakeError::{
            BadPattern, BadPayload, BadMessage, BadPreshare, IoErrorReadPayload,
            IoErrorWritePayload, IoErrorReadMessage, IoErrorWriteMessage,
        };
        use std::pin::Pin;

        type LocalBoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

        fn i<'a, A, H, Io, Rfn, R, Wfn, W, Pfn, P, Qfn, Q, MaxMessage, MaxPayload>(
            initiator: bool,
            state: HandshakeState<A, BaseHistory<A>>,
            io: Io,
            read_fn: &'a mut Rfn,
            write_fn: &'a mut Wfn,
            payload_read_fn: &'a mut Pfn,
            payload_write_fn: &'a mut Qfn,
        ) -> LocalBoxFuture<'a, Result<(HandshakeState<A, H>, bool, Io), HandshakeError>>
        where
            A: 'a + NoiseAlgorithm,
            H: History<A>,
            Io: 'a,
            Rfn: FnMut(Io, usize) -> R,
            R: Future<Output = Result<(GenericArray<u8, MaxMessage>, Io), io::Error>>,
            Wfn: FnMut(Io, usize, GenericArray<u8, MaxMessage>) -> W,
            W: Future<Output = Result<Io, io::Error>>,
            Pfn: FnMut(usize) -> P,
            P: Future<Output = Result<GenericArray<u8, MaxPayload>, io::Error>>,
            Qfn: FnMut(usize, GenericArray<u8, MaxPayload>) -> Q,
            Q: Future<Output = Result<(), io::Error>>,
            MaxMessage: ArrayLength<u8>,
            MaxPayload: ArrayLength<u8>,
        {
            let f = async move {
                if H::BASE {
                    return Ok((
                        HandshakeState::from_inner(state.initial_state),
                        initiator,
                        io,
                    ));
                }
                let three =
                    i::<A, H::Inner, Io, Rfn, R, Wfn, W, Pfn, P, Qfn, Q, MaxMessage, MaxPayload>(
                        initiator,
                        state,
                        io,
                        read_fn,
                        write_fn,
                        payload_read_fn,
                        payload_write_fn,
                    )
                    .await;
                let (inner, initiator, io) = three?;
                if H::HAS_PAYLOAD {
                    if initiator {
                        let mut array = GenericArray::default();
                        let length = <H::Output as LineValid>::Length::to_usize();
                        if length > 0 {
                            let buffer =
                                payload_read_fn(length).await.map_err(IoErrorReadPayload)?;
                            array.as_mut().clone_from_slice(&buffer[0..length]);
                        };
                        let output = <H::Output as LineValid>::try_clone_array(&array)
                            .map_err(BadPayload)?;
                        let (final_state, input) = H::give(inner, output);
                        let length = <H::Input as LineValid>::Length::to_usize();
                        let io = if length > 0 {
                            let mut buffer = GenericArray::default();
                            buffer[0..length].clone_from_slice(input.clone_line().as_ref());
                            write_fn(io, length, buffer)
                                .await
                                .map_err(IoErrorWriteMessage)?
                        } else {
                            io
                        };
                        Ok((final_state, !initiator, io))
                    } else {
                        let mut array = GenericArray::default();
                        let length = <H::Input as LineValid>::Length::to_usize();
                        let io = if length > 0 {
                            let (buffer, io) =
                                read_fn(io, length).await.map_err(IoErrorReadMessage)?;
                            array.as_mut().clone_from_slice(&buffer[0..length]);
                            io
                        } else {
                            io
                        };
                        let input =
                            <H::Input as LineValid>::try_clone_array(&array).map_err(BadMessage)?;
                        let (final_state, output) = H::take(inner, input)
                            .map_err(|(_, e)| e)
                            .map_err(BadPattern)?;
                        let length = <H::Output as LineValid>::Length::to_usize();
                        if length > 0 {
                            let mut buffer = GenericArray::default();
                            buffer[0..length].clone_from_slice(output.clone_line().as_ref());
                            payload_write_fn(length, buffer)
                                .await
                                .map_err(IoErrorWritePayload)?;
                        };
                        Ok((final_state, !initiator, io))
                    }
                } else {
                    let array = GenericArray::default();
                    let output =
                        <H::Output as LineValid>::try_clone_array(&array).map_err(BadPreshare)?;
                    let (final_state, _input) = H::give(inner, output);
                    Ok((final_state, initiator, io))
                }
            };
            Box::pin(f)
        }

        let (state, _, io) = i::<A, H, Io, Rfn, R, Wfn, W, Pfn, P, Qfn, Q, MaxMessage, MaxPayload>(
            initiator,
            self,
            io,
            read_fn,
            write_fn,
            payload_read_fn,
            payload_write_fn,
        )
        .await?;
        Ok((state.cipher(initiator), io))
    }
}

impl<A, H> HandshakeState<A, H>
where
    A: NoiseAlgorithm,
    H: History<A>,
{
    #[cfg(test)]
    pub fn transmute<G>(s: HandshakeState<A, G>) -> Self
    where
        G: History<A>,
    {
        HandshakeState {
            initial_state: s.initial_state,
            phantom_data: PhantomData,
        }
    }

    fn from_inner(state: State<A>) -> Self {
        HandshakeState {
            initial_state: state,
            phantom_data: PhantomData,
        }
    }

    pub fn take<E>(
        self,
        input: E::Input,
    ) -> Result<(HandshakeState<A, (H, E)>, E::Output), (Self, PatternError)>
    where
        E: Pattern<A>,
        (H, E): History<A>,
    {
        let original_state = HandshakeState::from_inner(self.initial_state.clone());

        let (state, output) =
            E::take(input, self.initial_state).map_err(|e| (original_state, e))?;
        Ok((HandshakeState::from_inner(state), output))
    }

    pub fn give<E>(self, output: E::Output) -> (HandshakeState<A, (H, E)>, E::Input)
    where
        E: Pattern<A>,
        (H, E): History<A>,
    {
        let (state, input) = E::give(self.initial_state, output);
        (HandshakeState::from_inner(state), input)
    }

    pub fn point<I>(&self) -> &A::Curve
    where
        I: Unsigned,
    {
        self.initial_state.point::<I>()
    }

    pub fn compressed<I>(&self) -> GenericArray<u8, <A::Curve as Curve>::CompressedLength>
    where
        I: Unsigned,
    {
        self.initial_state.compressed::<I>()
    }

    pub fn hash(&self) -> GenericArray<u8, HashLength<A>> {
        self.initial_state.hash()
    }

    pub fn cipher<R>(self, initiator: bool) -> CipherPair<A::CipherAlgorithm, R>
    where
        R: Rotor<A::CipherAlgorithm>,
    {
        self.initial_state.cipher(initiator)
    }
}

// the metadata of the handshake, contains all operations performed over the state
pub trait History<A>
where
    Self: Sized,
    A: NoiseAlgorithm,
{
    type Inner: History<A>;
    type Input: LineValid;
    type Output: LineValid;

    const BASE: bool;
    const NAME: &'static str;
    const HAS_PAYLOAD: bool;

    fn take(
        state: HandshakeState<A, Self::Inner>,
        input: Self::Input,
    ) -> Result<
        (HandshakeState<A, Self>, Self::Output),
        (HandshakeState<A, Self::Inner>, PatternError),
    >;

    fn give(
        state: HandshakeState<A, Self::Inner>,
        output: Self::Output,
    ) -> (HandshakeState<A, Self>, Self::Input);
}

pub struct BaseHistory<A>(PhantomData<A>)
where
    A: NoiseAlgorithm;

impl<A> History<A> for BaseHistory<A>
where
    A: NoiseAlgorithm,
{
    type Inner = Self;
    type Input = EmptyLine;
    type Output = EmptyLine;

    const BASE: bool = true;
    const NAME: &'static str = "base";
    const HAS_PAYLOAD: bool = false;

    fn take(
        state: HandshakeState<A, Self::Inner>,
        input: Self::Input,
    ) -> Result<
        (HandshakeState<A, Self>, Self::Output),
        (HandshakeState<A, Self::Inner>, PatternError),
    > {
        let _ = input;
        Ok((state, EmptyLine::default()))
    }

    fn give(
        state: HandshakeState<A, Self::Inner>,
        output: Self::Output,
    ) -> (HandshakeState<A, Self>, Self::Input) {
        let _ = output;
        (state, EmptyLine::default())
    }
}

impl<A, H, E> History<A> for (H, E)
where
    A: NoiseAlgorithm,
    H: History<A>,
    E: Pattern<A>,
    Concat<H::Input, E::Input>: LineValid,
{
    type Inner = H;
    type Input = E::Input;
    type Output = E::Output;

    const BASE: bool = false;
    const NAME: &'static str = "pattern";
    const HAS_PAYLOAD: bool = E::HAS_PAYLOAD;

    fn take(
        state: HandshakeState<A, Self::Inner>,
        input: Self::Input,
    ) -> Result<
        (HandshakeState<A, Self>, Self::Output),
        (HandshakeState<A, Self::Inner>, PatternError),
    > {
        let original_state = HandshakeState::from_inner(state.initial_state.clone());

        let (state, output) = E::take(input, state.initial_state)
            .map_err(|pattern_error| (original_state, pattern_error))?;
        Ok((HandshakeState::from_inner(state), output))
    }

    fn give(
        state: HandshakeState<A, Self::Inner>,
        output: Self::Output,
    ) -> (HandshakeState<A, Self>, Self::Input) {
        let (state, input) = E::give(state.initial_state, output);
        (HandshakeState::from_inner(state), input)
    }
}
