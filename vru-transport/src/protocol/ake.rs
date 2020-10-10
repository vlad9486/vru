use std::ops::Add;
use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
use vru_noise::{SymmetricState, ChainingKey, Key, Tag};
use rac::{LineValid, Line, Concat, Curve, generic_array::{GenericArray, sequence::GenericSequence, typenum}};
use super::lattice::{PkLattice, SkLattice, PkLatticeCl, PkLatticeCompressed};

pub struct PublicKey {
    elliptic: EdwardsPoint,
    lattice: PkLattice,
}

pub struct SecretKey {
    elliptic: Scalar,
    lattice: SkLattice,
}

pub fn key_pair<R>(rng: &mut R) -> (SecretKey, PublicKey)
where
    R: rand::Rng,
{
    let e_sk = Scalar::try_clone_array(&GenericArray::generate(|_| rng.gen())).unwrap();
    let e_pk = EdwardsPoint::base().exp_ec(&e_sk);
    let (pq_sk, pq_pk) = PkLattice::key_pair();

    (
        SecretKey {
            elliptic: e_sk,
            lattice: pq_sk,
        },
        PublicKey {
            elliptic: e_pk,
            lattice: pq_pk,
        },
    )
}

pub type PkEllipticCl = <EdwardsPoint as Curve>::CompressedLength;

pub struct PublicKeyCompressed {
    elliptic: GenericArray<u8, PkEllipticCl>,
    lattice: PkLatticeCompressed,
}

impl LineValid for PublicKeyCompressed {
    type Length = <PkEllipticCl as Add<PkLatticeCl>>::Output;

    fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
        LineValid::try_clone_array(a)
            .map(|Concat(elliptic, lattice)| PublicKeyCompressed {
                elliptic: elliptic,
                lattice: lattice,
            })
    }

    fn clone_line(&self) -> GenericArray<u8, Self::Length> {
        Concat(self.elliptic.clone(), self.lattice.clone()).clone_line()
    }
}

impl Line for PublicKeyCompressed {
    fn clone_array(a: &GenericArray<u8, Self::Length>) -> Self {
        Self::try_clone_array(a).unwrap()
    }
}

fn compress<R>(pk: &PublicKey, rng: &mut R) -> PublicKeyCompressed
where
    R: rand::Rng,
{
    PublicKeyCompressed {
        elliptic: Curve::compress(&pk.elliptic),
        lattice: pk.lattice.compress(rng),
    }
}

pub struct Encrypted<T>
where
    T: Line,
{
    data: T,
    tag: Tag<Noise>,
}

impl<T> LineValid for Encrypted<T>
where
    T: Line,
    Concat<GenericArray<u8, T::Length>, Tag<Noise>>: LineValid,
{
    type Length = <Concat<GenericArray<u8, T::Length>, Tag<Noise>> as LineValid>::Length;

    fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
        LineValid::try_clone_array(a)
            .map(|Concat(data, tag)| Encrypted {
                data: T::clone_array(&data),
                tag: tag,
            })
    }

    fn clone_line(&self) -> GenericArray<u8, Self::Length> {
        Concat(self.data.clone_line(), self.tag.clone()).clone_line()
    }
}

impl<T> Line for Encrypted<T>
where
    T: Line,
    Concat<GenericArray<u8, T::Length>, Tag<Noise>>: LineValid,
{
    fn clone_array(a: &GenericArray<u8, Self::Length>) -> Self {
        Self::try_clone_array(a).unwrap()
    }
}

type Noise = (sha3::Sha3_512, byteorder::LittleEndian, chacha20poly1305::ChaCha20Poly1305);

pub struct HasMessage<S, M> {
    state: S,
    message: M,
}

impl<S, M> HasMessage<S, M> {
    pub fn take_message<F>(self, mut f: F) -> S
    where
        F: FnMut(M),
    {
        match self {
            HasMessage { state, message } => {
                f(message);
                state
            }
        }
    }
}

pub trait AppendMessage
where
    Self: Sized,
{
    fn give_message<M>(self, message: M) -> HasMessage<Self, M>;
}

impl<S> AppendMessage for S {
    fn give_message<M>(self, message: M) -> HasMessage<Self, M> {
        HasMessage {
            state: self,
            message: message,
        }
    }
}

pub struct State {
    symmetric_state: SymmetricState<Noise, ChainingKey<Noise>>,
}

pub struct StateI {
    symmetric_state: SymmetricState<Noise, Key<Noise, typenum::U1>>,
    e_sk: SecretKey,
}

pub struct Message0 {
    e_pk: PublicKeyCompressed,
    tag: Tag<Noise>,
}

pub struct Message1 {
    s_pk: Encrypted<PublicKeyCompressed>,
    tag: Tag<Noise>,
}

impl State {
    pub fn new(s_pk: &PublicKey) -> Self {    
        State {
            symmetric_state: SymmetricState::new("Noise_XK_25519_Kyber_ChaChaPoly_SHA3/512")
                .mix_hash(b"vru")
                .mix_hash(&Curve::compress(&s_pk.elliptic))
                .mix_hash(s_pk.lattice.as_ref()),
        }
    }

    pub fn generate<R>(self, rng: &mut R, peer_s_pk: &PublicKey) -> HasMessage<StateI, Message0>
    where
        R: rand::Rng,
    {
        let (e_sk, e_pk) = key_pair(rng);
        let e_pk_c = compress(&e_pk, rng);
        let mut tag = GenericArray::default();

        match self {
            State { symmetric_state } => StateI {
                symmetric_state: symmetric_state
                    .mix_hash(&e_pk_c.elliptic)
                    .mix_hash(&e_pk_c.lattice)
                    .mix_shared_secret(&Curve::compress(&peer_s_pk.elliptic.exp_ec(&e_sk.elliptic)))
                    .encrypt(&mut [])
                    .destruct(|t| tag = t),
                e_sk: e_sk,
            }
            .give_message(Message0 {
                e_pk: e_pk_c,
                tag: tag,
            })
        }
    }
}

impl HasMessage<State, Message0> {
    pub fn consume(self, s_sk: &SecretKey) -> HasMessage<StateI, Message1> {
        let _ = s_sk;
        unimplemented!()
    }
}
