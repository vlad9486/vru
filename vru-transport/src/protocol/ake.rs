use std::ops::Add;
use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
use vru_noise::{SymmetricState, Cipher, Rotor, ChainingKey, Key, Tag};
use rac::{
    LineValid, Line, Concat, Curve,
    generic_array::{GenericArray, sequence::GenericSequence, typenum},
};
use super::lattice::{PkLattice, SkLattice, PkLatticeCl, PkLatticeCompressed, CipherText};

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
        LineValid::try_clone_array(a).map(|Concat(elliptic, lattice)| PublicKeyCompressed {
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

fn decompress(pk_c: &PublicKeyCompressed) -> PublicKey {
    PublicKey {
        elliptic: Curve::decompress(&pk_c.elliptic).unwrap(),
        lattice: PkLattice::decompress(&pk_c.lattice),
    }
}

pub struct Encrypted<T>
where
    T: Line,
{
    data: GenericArray<u8, T::Length>,
    tag: Tag<Noise>,
}

impl<T> Encrypted<T>
where
    T: Line,
{
    pub fn new(v: T) -> Self {
        Encrypted {
            data: v.clone_line(),
            tag: GenericArray::default(),
        }
    }
}

impl<T> LineValid for Encrypted<T>
where
    T: Line,
    Concat<GenericArray<u8, T::Length>, Tag<Noise>>: LineValid,
{
    type Length = <Concat<GenericArray<u8, T::Length>, Tag<Noise>> as LineValid>::Length;

    fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
        LineValid::try_clone_array(a).map(|Concat(data, tag)| Encrypted {
            data: data,
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

type Noise = (
    sha3::Sha3_512,
    byteorder::LittleEndian,
    chacha20poly1305::ChaCha20Poly1305,
);

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
            },
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

pub struct StateF {
    symmetric_state: SymmetricState<Noise, Key<Noise, typenum::U1>>,
}

// generate: State -> StateI, Message0
type Message0 = Concat<PublicKeyCompressed, Tag<Noise>>;
// consume: State, Message0 -> StateI, Message1
type Message1 = Concat<Concat<PublicKeyCompressed, CipherText>, Tag<Noise>>;
// generate: StateI, Message1 -> StateF, Message2
type Message2 = Concat<Concat<Encrypted<PublicKeyCompressed>, Encrypted<CipherText>>, Tag<Noise>>;
// consume: StateI, Message2 -> StateF, Message3, PublicKey
type Message3 = Concat<Encrypted<CipherText>, Tag<Noise>>;
// generate: StateF, Message3 -> Cipher, Message4
type Message4 = Concat<Encrypted<CipherText>, Tag<Noise>>;
// consume: StateF, Message2 -> Cipher

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
        match self {
            State { symmetric_state } => {
                let (e_sk, e_pk) = key_pair(rng);
                let e_pk_c = compress(&e_pk, rng);
                let mut tag = GenericArray::default();

                let symmetric_state = symmetric_state
                    .mix_hash(&e_pk_c.elliptic)
                    .mix_hash(&e_pk.lattice.as_ref())
                    .mix_shared_secret(&Curve::compress(&peer_s_pk.elliptic.exp_ec(&e_sk.elliptic)))
                    .encrypt(&mut [])
                    .destruct(|t| tag = t);

                StateI {
                    symmetric_state: symmetric_state,
                    e_sk: e_sk,
                }
                .give_message(Concat(e_pk_c, tag))
            },
        }
    }
}

impl HasMessage<State, Message0> {
    pub fn consume<R>(
        self,
        rng: &mut R,
        s_sk: &SecretKey,
    ) -> Result<HasMessage<StateI, Message1>, ()>
    where
        R: rand::Rng,
    {
        match self {
            HasMessage {
                state: State { symmetric_state },
                message: Concat(peer_e_pk_c, mut tag),
            } => {
                let peer_e_pk = decompress(&peer_e_pk_c);
                let peer_e_pq = peer_e_pk.lattice.encapsulate();

                let (e_sk, e_pk) = key_pair(rng);
                let e_pk_c = compress(&e_pk, rng);

                let symmetric_state = symmetric_state
                    .mix_hash(&peer_e_pk_c.elliptic)
                    .mix_hash(&peer_e_pk.lattice.as_ref())
                    .mix_shared_secret(&Curve::compress(&peer_e_pk.elliptic.exp_ec(&s_sk.elliptic)))
                    .decrypt(&mut [], tag)?
                    .mix_hash(&e_pk_c.elliptic)
                    .mix_hash(&e_pk.lattice.as_ref())
                    .mix_shared_secret(&Curve::compress(&peer_e_pk.elliptic.exp_ec(&e_sk.elliptic)))
                    .mix_shared_secret(&peer_e_pq.ss)
                    .encrypt(&mut [])
                    .destruct(|t| tag = t);

                Ok(HasMessage {
                    state: StateI {
                        symmetric_state: symmetric_state,
                        e_sk: e_sk,
                    },
                    message: Concat(Concat(e_pk_c, peer_e_pq.ct), tag),
                })
            },
        }
    }
}

impl HasMessage<StateI, Message1> {
    pub fn generate<R>(
        self,
        rng: &mut R,
        s_sk: &SecretKey,
        s_pk: &PublicKey,
        peer_s_pk: &PublicKey,
    ) -> Result<HasMessage<StateF, Message2>, ()>
    where
        R: rand::Rng,
    {
        match self {
            HasMessage {
                state:
                    StateI {
                        symmetric_state,
                        e_sk,
                    },
                message: Concat(Concat(peer_e_pk_c, e_ct), mut tag),
            } => {
                let peer_e_pk = decompress(&peer_e_pk_c);
                let e_ss = PkLattice::decapsulate(&e_sk.lattice, &e_ct);
                let mut encrypted_s_pk = Encrypted::new(compress(&s_pk, rng));
                let peer_e_pq = peer_s_pk.lattice.encapsulate();
                let mut encrypted_peer_e_ct = Encrypted::new(peer_e_pq.ct);

                let symmetric_state = symmetric_state
                    .mix_hash(&peer_e_pk_c.elliptic)
                    .mix_hash(&peer_e_pk.lattice.as_ref())
                    .mix_shared_secret(&Curve::compress(&peer_e_pk.elliptic.exp_ec(&e_sk.elliptic)))
                    .mix_shared_secret(&e_ss)
                    .decrypt(&mut [], tag)?
                    .encrypt(encrypted_s_pk.data.as_mut_slice())
                    .destruct(|t| encrypted_s_pk.tag = t)
                    .encrypt(encrypted_peer_e_ct.data.as_mut_slice())
                    .destruct(|t| encrypted_peer_e_ct.tag = t)
                    .mix_shared_secret(&Curve::compress(&peer_e_pk.elliptic.exp_ec(&s_sk.elliptic)))
                    .mix_shared_secret(&peer_e_pq.ss)
                    .encrypt(&mut [])
                    .destruct(|t| tag = t);

                Ok(HasMessage {
                    state: StateF {
                        symmetric_state: symmetric_state,
                    },
                    message: Concat(Concat(encrypted_s_pk, encrypted_peer_e_ct), tag),
                })
            },
        }
    }
}

impl HasMessage<StateI, Message2> {
    pub fn consume(
        self,
        s_sk: &SecretKey,
    ) -> Result<(HasMessage<StateF, Message3>, PublicKey), ()> {
        match self {
            HasMessage {
                state:
                    StateI {
                        symmetric_state,
                        e_sk,
                    },
                message: Concat(Concat(mut encrypted_peer_s_pk, mut encrypted_e_ct), mut tag),
            } => {
                let peer_s_pk_c;
                let peer_s_pk;
                let mut encrypted_peer_s_ct;
                let peer_s_ss;

                let symmetric_state = symmetric_state
                    .decrypt(
                        encrypted_peer_s_pk.data.as_mut_slice(),
                        encrypted_peer_s_pk.tag,
                    )?
                    .decrypt(encrypted_e_ct.data.as_mut_slice(), encrypted_e_ct.tag)?
                    .mix_shared_secret({
                        peer_s_pk_c = Line::clone_array(&encrypted_peer_s_pk.data);
                        peer_s_pk = decompress(&peer_s_pk_c);
                        let peer_s_pq = peer_s_pk.lattice.encapsulate();
                        encrypted_peer_s_ct = Encrypted::new(peer_s_pq.ct);
                        peer_s_ss = peer_s_pq.ss;
                        &Curve::compress(&peer_s_pk.elliptic.exp_ec(&e_sk.elliptic))
                    })
                    .mix_shared_secret({
                        PkLattice::decapsulate(&s_sk.lattice, &encrypted_e_ct.data).as_ref()
                    })
                    .decrypt(&mut [], tag)?
                    .encrypt(encrypted_peer_s_ct.data.as_mut())
                    .destruct(|t| encrypted_peer_s_ct.tag = t)
                    .mix_shared_secret(&peer_s_ss)
                    .encrypt(&mut [])
                    .destruct(|t| tag = t);

                Ok((
                    HasMessage {
                        state: StateF {
                            symmetric_state: symmetric_state,
                        },
                        message: Concat(encrypted_peer_s_ct, tag),
                    },
                    peer_s_pk,
                ))
            },
        }
    }
}

impl HasMessage<StateF, Message3> {
    pub fn generate<R>(
        self,
        s_sk: &SecretKey,
        s_peer_pk: &PublicKey,
        payload: &mut [u8],
    ) -> Result<HasMessage<Cipher<Noise, R>, Message4>, ()>
    where
        R: Rotor<Noise>,
    {
        match self {
            HasMessage {
                state: StateF { symmetric_state },
                message: Concat(mut encrypted_s_ct, mut tag),
            } => {
                let peer_s_pq = s_peer_pk.lattice.encapsulate();
                let mut encrypted_peer_s_ct = Encrypted::new(peer_s_pq.ct);
                let cipher = symmetric_state
                    .decrypt(encrypted_s_ct.data.as_mut(), encrypted_s_ct.tag)?
                    .mix_shared_secret({
                        PkLattice::decapsulate(&s_sk.lattice, &encrypted_s_ct.data).as_ref()
                    })
                    .decrypt(payload, tag)?
                    .encrypt(encrypted_peer_s_ct.data.as_mut())
                    .destruct(|t| encrypted_peer_s_ct.tag = t)
                    .mix_shared_secret(peer_s_pq.ss.as_ref())
                    .encrypt(payload)
                    .destruct(|t| tag = t)
                    .finish();

                Ok(HasMessage {
                    state: cipher,
                    message: Concat(encrypted_peer_s_ct, tag),
                })
            },
        }
    }
}

impl HasMessage<StateF, Message4> {
    pub fn consume<R>(self, s_sk: &SecretKey, payload: &mut [u8]) -> Result<Cipher<Noise, R>, ()>
    where
        R: Rotor<Noise>,
    {
        match self {
            HasMessage {
                state: StateF { symmetric_state },
                message: Concat(mut encrypted_s_ct, tag),
            } => {
                let cipher = symmetric_state
                    .decrypt(encrypted_s_ct.data.as_mut(), encrypted_s_ct.tag)?
                    .mix_shared_secret({
                        PkLattice::decapsulate(&s_sk.lattice, &encrypted_s_ct.data).as_ref()
                    })
                    .decrypt(payload, tag)?
                    .finish();

                Ok(cipher)
            },
        }
    }
}
