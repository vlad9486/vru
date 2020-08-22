use super::{
    traits::{NoiseAlgorithm, HashLength, AeadKey, EncryptedPayload, CompressedCurve, Rotor},
    cipher_state::CipherPair,
    symmetric_state::SymmetricState,
};

use core::cell::RefCell;
use rac::{LineValid, Curve};
use generic_array::{
    GenericArray,
    typenum::{Unsigned, Bit},
};

enum Point<C>
where
    C: Curve,
{
    NotSetup,
    Public {
        public: C,
        cache: RefCell<Option<CompressedCurve<C>>>,
    },
    Pair {
        public: C,
        secret: C::Scalar,
        cache: RefCell<Option<CompressedCurve<C>>>,
    },
}

impl<C> Point<C>
where
    C: Curve,
{
    pub fn new() -> Self {
        Point::NotSetup
    }

    pub fn from_public(public: C) -> Self {
        Point::Public {
            public: public,
            cache: RefCell::new(None),
        }
    }

    pub fn from_secret(secret: C::Scalar) -> Self {
        Point::Pair {
            public: C::base().exp_ec(&secret),
            secret: secret,
            cache: RefCell::new(None),
        }
    }

    pub fn from_compressed(a: &CompressedCurve<C>) -> Result<Self, ()> {
        let public = C::decompress(a)?;
        Ok(Point::Public {
            public: public,
            cache: RefCell::new(Some(a.clone())),
        })
    }

    pub fn public(&self) -> Option<&C> {
        match self {
            &Point::NotSetup => None,
            &Point::Public {
                public: ref public,
                cache: _,
            } => Some(public),
            &Point::Pair {
                public: ref public,
                secret: _,
                cache: _,
            } => Some(public),
        }
    }

    pub fn compressed(&self) -> Option<CompressedCurve<C>> {
        let cache = match self {
            &Point::NotSetup => None,
            &Point::Public {
                public: _,
                cache: ref cache,
            } => Some(cache),
            &Point::Pair {
                public: _,
                secret: _,
                cache: ref cache,
            } => Some(cache),
        }?;
        let value = cache.replace(None);
        let a = match value {
            Some(a) => a,
            None => self.public()?.compress(),
        };
        assert_eq!(cache.replace(Some(a.clone())), None);
        Some(a)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum StateError {
    TagMismatch,
    InvalidPoint,
    InvalidPayload,
}

pub struct State<A>
where
    A: NoiseAlgorithm,
{
    symmetric_state: SymmetricState<A>,
    points: [Point<A::Curve>; 4],
    psk: Option<AeadKey<A::CipherAlgorithm>>,
}

impl<A> State<A>
where
    A: NoiseAlgorithm,
{
    pub fn new(name: &str, prologue: &[u8]) -> Self {
        State {
            symmetric_state: {
                let mut symmetric_state = SymmetricState::new(name);
                symmetric_state.mix_hash(&prologue);
                symmetric_state
            },
            points: [Point::new(), Point::new(), Point::new(), Point::new()],
            psk: None,
        }
    }

    pub fn with_psk(self, psk: AeadKey<A::CipherAlgorithm>) -> Self {
        let mut s = self;
        s.psk = Some(psk);
        s
    }

    pub fn with_point<I>(self, point: A::Curve) -> Self
    where
        I: Unsigned,
    {
        let mut s = self;
        s.points[I::to_usize()] = Point::from_public(point);
        s
    }

    pub fn with_secret<I>(self, secret: <A::Curve as Curve>::Scalar) -> Self
    where
        I: Unsigned,
    {
        let mut s = self;
        s.points[I::to_usize()] = Point::from_secret(secret);
        s
    }

    pub fn store_compressed<I>(
        &mut self,
        compressed: &CompressedCurve<A::Curve>,
    ) -> Result<(), StateError>
    where
        I: Unsigned,
    {
        self.points[I::to_usize()] =
            Point::from_compressed(compressed).map_err(|()| StateError::InvalidPoint)?;
        Ok(())
    }

    pub fn cipher<R>(self, initiator: bool) -> CipherPair<A::CipherAlgorithm, R>
    where
        R: Rotor<A::CipherAlgorithm>,
    {
        self.symmetric_state.split(!initiator)
    }

    pub fn hash(&self) -> GenericArray<u8, HashLength<A>> {
        self.symmetric_state.hash()
    }

    pub fn encrypt<T>(&mut self, plain: &T) -> EncryptedPayload<A, T>
    where
        T: LineValid,
        EncryptedPayload<A, T>: LineValid,
    {
        self.symmetric_state.encrypt::<T>(plain)
    }

    pub fn decrypt<T>(&mut self, encrypted: EncryptedPayload<A, T>) -> Result<T, StateError>
    where
        T: LineValid,
        EncryptedPayload<A, T>: LineValid,
    {
        use either::Either;

        self.symmetric_state
            .decrypt::<T>(encrypted)
            .map_err(|e| match e {
                Either::Left(()) => StateError::TagMismatch,
                Either::Right(()) => StateError::InvalidPayload,
            })
    }

    pub fn mix_hash<I, B>(&mut self)
    where
        I: Unsigned,
        B: Bit,
    {
        let a = self.points[I::to_usize()]
            .compressed()
            .unwrap_or_else(|| panic!("key U{} should be store before use", I::to_usize()));
        self.symmetric_state.mix_hash(&a);
        if self.psk.is_some() && B::to_bool() {
            self.symmetric_state.mix_key_single(&a)
        }
    }

    pub fn mix_key<I, J>(&mut self)
    where
        I: Unsigned,
        J: Unsigned,
    {
        let i = &self.points[I::to_usize()];
        let j = &self.points[J::to_usize()];
        match (i, j) {
            (
                &Point::Public {
                    public: ref public,
                    cache: _,
                },
                &Point::Pair {
                    public: _,
                    secret: ref secret,
                    cache: _,
                },
            ) => self.symmetric_state.mix_key(public, secret),
            (
                &Point::Pair {
                    public: _,
                    secret: ref secret,
                    cache: _,
                },
                &Point::Public {
                    public: ref public,
                    cache: _,
                },
            ) => self.symmetric_state.mix_key(public, secret),
            _ => panic!(
                "one of either U{} or U{} should has secret key, another should has public key\n\
                 now it's {:?} and {:?}",
                I::to_usize(),
                J::to_usize(),
                i,
                j
            ),
        };
    }

    pub fn mix_psk(&mut self) {
        let psk_ref = self
            .psk
            .as_ref()
            .unwrap_or_else(|| panic!("preshared key should be store before use"))
            .clone_line();
        self.symmetric_state.mix_psk(&psk_ref)
    }

    pub fn point<I>(&self) -> &A::Curve
    where
        I: Unsigned,
    {
        &self.points[I::to_usize()]
            .public()
            .unwrap_or_else(|| panic!("key U{} should be store before use", I::to_usize()))
    }

    pub fn compressed<I>(&self) -> CompressedCurve<A::Curve>
    where
        I: Unsigned,
    {
        self.points[I::to_usize()]
            .compressed()
            .unwrap_or_else(|| panic!("key U{} should be store before use", I::to_usize()))
    }

    pub fn zeroize_points<F>(&mut self, op: F)
    where
        F: Fn(&mut <A::Curve as Curve>::Scalar),
    {
        self.points.iter_mut().for_each(|p| match p {
            &mut Point::Pair {
                public: _,
                secret: ref mut secret,
                cache: _,
            } => op(secret),
            _ => (),
        })
    }
}

mod implementations {
    use super::{Point, State};
    use crate::state::NoiseAlgorithm;

    use core::fmt;
    use rac::{LineValid, Curve};

    impl<C> fmt::Debug for Point<C>
    where
        C: Curve,
    {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                &Point::NotSetup => f.debug_tuple("NotSetup").finish(),
                &Point::Public {
                    public: ref public,
                    cache: _,
                } => f
                    .debug_tuple("Public")
                    .field(&hex::encode(public.compress()))
                    .finish(),
                &Point::Pair {
                    public: ref public,
                    cache: _,
                    secret: ref secret,
                } => f
                    .debug_tuple("Pair")
                    .field(&hex::encode(public.compress()))
                    .field(&hex::encode(secret.clone_line()))
                    .finish(),
            }
        }
    }

    impl<C> PartialEq for Point<C>
    where
        C: Curve,
    {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (&Point::NotSetup, &Point::NotSetup) => true,
                (
                    &Point::Public {
                        public: ref lhs_public,
                        cache: _,
                    },
                    &Point::Public {
                        public: ref rhs_public,
                        cache: _,
                    },
                ) => lhs_public.clone_line() == rhs_public.clone_line(),
                (
                    &Point::Pair {
                        public: _,
                        secret: ref lhs_secret,
                        cache: _,
                    },
                    &Point::Pair {
                        public: _,
                        secret: ref rhs_secret,
                        cache: _,
                    },
                ) => lhs_secret.clone_line() == rhs_secret.clone_line(),
                _ => false,
            }
        }
    }

    impl<C> Eq for Point<C> where C: Curve {}

    impl<C> Clone for Point<C>
    where
        C: Curve,
    {
        fn clone(&self) -> Self {
            match self {
                &Point::NotSetup => Point::NotSetup,
                &Point::Public {
                    public: ref public,
                    cache: ref cache,
                } => Point::Public {
                    public: C::try_clone_array(&public.clone_line()).unwrap(),
                    cache: cache.clone(),
                },
                &Point::Pair {
                    public: ref public,
                    secret: ref secret,
                    cache: ref cache,
                } => Point::Pair {
                    public: C::try_clone_array(&public.clone_line()).unwrap(),
                    secret: <C::Scalar as LineValid>::try_clone_array(&secret.clone_line())
                        .unwrap(),
                    cache: cache.clone(),
                },
            }
        }
    }

    impl<A> Clone for State<A>
    where
        A: NoiseAlgorithm,
    {
        fn clone(&self) -> Self {
            State {
                symmetric_state: self.symmetric_state.clone(),
                points: self.points.clone(),
                psk: match &self.psk {
                    &None => None,
                    &Some(ref psk) => Some(psk.clone()),
                },
            }
        }
    }
}
