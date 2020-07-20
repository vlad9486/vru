use rac::LineValid;
use either::Either;
use super::EmptyLine;

/// Abstraction over enumeration of sessions
pub trait Choose {
    type Branch: Session;
    type Inner: Choose;

    fn choose(self) -> Either<Self::Branch, Self::Inner>;
}

/// Base of choosing recursion, needed for type-checker
pub enum Choose0 {}

impl Choose for Choose0 {
    type Branch = !;
    type Inner = Choose0;

    fn choose(self) -> Either<Self::Branch, Self::Inner> {
        match self {}
    }
}

/// Trivial choose, only one variant available
pub enum Choose1<_0>
where
    _0: Session,
{
    _0(_0),
}

impl<_0> Choose for Choose1<_0>
where
    _0: Session,
{
    type Branch = _0;
    type Inner = Choose0;

    fn choose(self) -> Either<Self::Branch, Self::Inner> {
        match self {
            Choose1::_0(_0) => Either::Left(_0),
        }
    }
}

/// Minimal choose
pub enum Choose2<_0, _1>
where
    _0: Session,
    _1: Session,
{
    _0(_0),
    _1(_1),
}

impl<_0, _1> Choose for Choose2<_0, _1>
where
    _0: Session,
    _1: Session,
{
    type Branch = _0;
    type Inner = Choose1<_1>;

    fn choose(self) -> Either<Self::Branch, Self::Inner> {
        match self {
            Choose2::_0(_0) => Either::Left(_0),
            Choose2::_1(_1) => Either::Right(Choose1::_0(_1)),
        }
    }
}

// TODO: macros
/// Choose one of three
pub enum Choose3<_0, _1, _2>
where
    _0: Session,
    _1: Session,
    _2: Session,
{
    _0(_0),
    _1(_1),
    _2(_2),
}

impl<_0, _1, _2> Choose for Choose3<_0, _1, _2>
where
    _0: Session,
    _1: Session,
    _2: Session,
{
    type Branch = _0;
    type Inner = Choose2<_1, _2>;

    fn choose(self) -> Either<Self::Branch, Self::Inner> {
        match self {
            Choose3::_0(_0) => Either::Left(_0),
            Choose3::_1(_1) => Either::Right(Choose2::_0(_1)),
            Choose3::_2(_2) => Either::Right(Choose2::_1(_2)),
        }
    }
}

/// Type-level communication session
pub trait Session {
    /// type of received value
    type Receive: LineValid;

    /// type of value that will be sent
    type Send: LineValid;

    /// choose the continuation of the session
    type Choose: Choose;

    /// whatever the session is end,
    /// use unit type as a continuation in order to mark the end of the session
    const END: bool = false;

    /// Perform the recursive step, receive some value through network,
    /// make some computation, send some value through network
    /// and choose the continuation of the session
    fn step(self, input: Self::Receive) -> (Self::Send, Self::Choose);
}

/// Absurd, needed for type-checker
impl Session for ! {
    type Receive = EmptyLine;
    type Send = EmptyLine;
    type Choose = Choose0;

    fn step(self, input: Self::Receive) -> (Self::Send, Self::Choose) {
        let _ = input;
        match self {}
    }
}

/// End of the session
impl Session for () {
    type Receive = EmptyLine;
    type Send = EmptyLine;
    type Choose = Choose1<()>;

    const END: bool = true;

    fn step(self, input: Self::Receive) -> (Self::Send, Self::Choose) {
        (input, self.into())
    }
}

impl<S> From<S> for Choose1<S>
where
    S: Session,
{
    fn from(v: S) -> Self {
        Choose1::_0(v)
    }
}
