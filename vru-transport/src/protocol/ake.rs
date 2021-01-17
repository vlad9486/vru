use std::{ops::Add, marker::PhantomData, fmt, str::FromStr};
use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
use vru_noise::{SymmetricState, Cipher, Unidirectional, Rotor, ChainingKey, Key, Tag};
use rac::{
    LineValid, Line, Concat, Curve,
    generic_array::{GenericArray, typenum},
};
use serde::{Serialize, Deserialize};
use super::lattice::{PkLattice, SkLattice, PkLatticeCl, PkLatticeCompressed, CipherText};

#[derive(Clone, Debug)]
pub struct PublicKey {
    elliptic: EdwardsPoint,
    lattice: PkLattice,
}

#[derive(Clone)]
pub struct SecretKey {
    elliptic: Scalar,
    lattice: SkLattice,
}

impl PublicKey {
    pub fn key_pair<R>(rng: &mut R) -> (SecretKey, Self)
    where
        R: rand::Rng,
    {
        let mut seed = [0; 96];
        rng.fill_bytes(seed.as_mut());
        Self::key_pair_fixed(seed)
    }

    pub fn key_pair_fixed(secret: [u8; 96]) -> (SecretKey, Self) {
        let e_sk = Scalar::try_clone_array(&GenericArray::from_slice(&secret[..32])).unwrap();
        let e_pk = EdwardsPoint::base().exp_ec(&e_sk);
        let (pq_sk, pq_pk) = PkLattice::key_pair(GenericArray::from_slice(&secret[32..]));

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
}

pub struct PublicKeyCompressed {
    elliptic: GenericArray<u8, <EdwardsPoint as Curve>::CompressedLength>,
    lattice: PkLatticeCompressed,
}

impl LineValid for PublicKeyCompressed {
    type Length = <<EdwardsPoint as Curve>::CompressedLength as Add<PkLatticeCl>>::Output;

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

fn compress(pk: &PublicKey) -> PublicKeyCompressed {
    PublicKeyCompressed {
        elliptic: Curve::compress(&pk.elliptic),
        lattice: pk.lattice.compress(),
    }
}

fn decompress(pk_c: &PublicKeyCompressed) -> PublicKey {
    PublicKey {
        elliptic: Curve::decompress(&pk_c.elliptic).unwrap(),
        lattice: PkLattice::decompress(&pk_c.lattice),
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct PublicIdentity {
    elliptic: GenericArray<u8, <EdwardsPoint as Curve>::CompressedLength>,
    lattice: GenericArray<u8, typenum::U32>,
}

impl PublicIdentity {
    pub fn new(pk: &PublicKey) -> Self {
        PublicIdentity {
            elliptic: Curve::compress(&pk.elliptic),
            lattice: pk.lattice.hash(),
        }
    }
}

impl fmt::Display for PublicIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bytes = [0b10111110; 66];
        bytes[2..34].clone_from_slice(self.elliptic.clone_line().as_ref());
        bytes[34..].clone_from_slice(self.lattice.as_ref());
        write!(f, "{}", base64::encode(bytes))
    }
}

impl FromStr for PublicIdentity {
    type Err = base64::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = base64::decode(s)?;
        let mut elliptic_array = GenericArray::default();
        elliptic_array
            .as_mut_slice()
            .clone_from_slice(&bytes[2..34]);
        let mut lattice_array = GenericArray::default();
        lattice_array.as_mut_slice().clone_from_slice(&bytes[34..]);
        Ok(PublicIdentity {
            elliptic: elliptic_array,
            lattice: lattice_array,
        })
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

    pub fn extract(self) -> T {
        T::clone_array(&self.data)
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
    sha2::Sha256,
    byteorder::LittleEndian,
    chacha20poly1305::ChaCha20Poly1305,
);

pub struct State {
    symmetric_state: SymmetricState<Noise, ChainingKey<Noise>>,
}

pub struct StateEphemeral {
    symmetric_state: SymmetricState<Noise, Key<Noise, typenum::U1>>,
    e_sk: SecretKey,
    e_pk: PublicKey,
}

pub struct StateFinal {
    symmetric_state: SymmetricState<Noise, Key<Noise, typenum::U1>>,
}

// generate: State -> StateI, Message0
pub type Message0 = Concat<PublicKeyCompressed, Tag<Noise>>;
// consume: State, Message0 -> StateI, Message1
pub type Message1 = Concat<Concat<PublicKeyCompressed, CipherText>, Tag<Noise>>;
// generate: StateI, Message1 -> StateF, Message2
pub type Message2 =
    Concat<Concat<Encrypted<PublicKeyCompressed>, Encrypted<CipherText>>, Tag<Noise>>;
// consume: StateI, Message2 -> StateF, Message3, PublicKey
pub type Message3 = Concat<Concat<Encrypted<PkLattice>, Encrypted<CipherText>>, Tag<Noise>>;
// generate: StateF, Message3 -> Cipher, Message4
pub type Message4<P> = Concat<Encrypted<CipherText>, Encrypted<P>>;
// consume: StateF, Message2 -> Cipher

impl State {
    pub fn new(s_pi: &PublicIdentity) -> Self {
        State {
            symmetric_state: SymmetricState::new("Noise_XK_25519+Kyber_ChaChaPoly_SHA256")
                .mix_hash(b"vru")
                .mix_hash(&s_pi.elliptic)
                .mix_hash(s_pi.lattice.as_ref()),
        }
    }

    pub fn generate<R>(
        self,
        rng: &mut R,
        peer_s_pi: &PublicIdentity,
    ) -> Result<(StateEphemeral, Message0), ()>
    where
        R: rand::Rng,
    {
        match self {
            State { symmetric_state } => {
                let (e_sk, e_pk) = PublicKey::key_pair(rng);
                let e_pk_c = compress(&e_pk);
                let peer_s_pk_elliptic: EdwardsPoint = Curve::decompress(&peer_s_pi.elliptic)?;
                let mut tag = GenericArray::default();

                let symmetric_state = symmetric_state
                    .mix_hash(&e_pk_c.elliptic)
                    .mix_hash(&e_pk.lattice.clone_line())
                    .mix_shared_secret(&Curve::compress(&peer_s_pk_elliptic.exp_ec(&e_sk.elliptic)))
                    .encrypt(&mut [])
                    .destruct(|t| tag = t);

                Ok((
                    StateEphemeral {
                        symmetric_state: symmetric_state,
                        e_sk: e_sk,
                        e_pk: e_pk,
                    },
                    Concat(e_pk_c, tag),
                ))
            },
        }
    }

    pub fn consume<R>(
        self,
        message: Message0,
        rng: &mut R,
        s_sk: &SecretKey,
    ) -> Result<(StateEphemeral, Message1), ()>
    where
        R: rand::Rng,
    {
        let Concat(peer_e_pk_c, mut tag) = message;
        match self {
            State { symmetric_state } => {
                let peer_e_pk = decompress(&peer_e_pk_c);
                let peer_e_pq = peer_e_pk.lattice.encapsulate(rng);

                let (e_sk, e_pk) = PublicKey::key_pair(rng);
                let e_pk_c = compress(&e_pk);

                let symmetric_state = symmetric_state
                    .mix_hash(&peer_e_pk_c.elliptic)
                    .mix_hash(&peer_e_pk.lattice.clone_line())
                    .mix_shared_secret(&Curve::compress(&peer_e_pk.elliptic.exp_ec(&s_sk.elliptic)))
                    .decrypt(&mut [], tag)?
                    .mix_hash(&e_pk_c.elliptic)
                    .mix_hash(&e_pk.lattice.clone_line())
                    .mix_shared_secret(&Curve::compress(&peer_e_pk.elliptic.exp_ec(&e_sk.elliptic)))
                    .mix_shared_secret(&peer_e_pq.ss)
                    .encrypt(&mut [])
                    .destruct(|t| tag = t);

                Ok((
                    StateEphemeral {
                        symmetric_state: symmetric_state,
                        e_sk: e_sk,
                        e_pk: e_pk,
                    },
                    Concat(Concat(e_pk_c, peer_e_pq.ct), tag),
                ))
            },
        }
    }
}

impl StateEphemeral {
    pub fn generate<R>(
        self,
        message: Message1,
        rng: &mut R,
        s_sk: &SecretKey,
        s_pk: &PublicKey,
    ) -> Result<(StateFinal, Message2), ()>
    where
        R: rand::Rng,
    {
        let Concat(Concat(peer_e_pk_c, e_ct), mut tag) = message;
        match self {
            StateEphemeral {
                symmetric_state,
                e_sk,
                e_pk,
            } => {
                let peer_e_pk = decompress(&peer_e_pk_c);
                let e_ss = PkLattice::decapsulate(&e_pk.lattice, &e_sk.lattice, &e_ct);
                let mut encrypted_s_pk = Encrypted::new(compress(&s_pk));
                let peer_e_pq = peer_e_pk.lattice.encapsulate(rng);
                let mut encrypted_peer_e_ct = Encrypted::new(peer_e_pq.ct);

                let symmetric_state = symmetric_state
                    .mix_hash(&peer_e_pk_c.elliptic)
                    .mix_hash(&peer_e_pk.lattice.clone_line())
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

                Ok((
                    StateFinal {
                        symmetric_state: symmetric_state,
                    },
                    Concat(Concat(encrypted_s_pk, encrypted_peer_e_ct), tag),
                ))
            },
        }
    }

    pub fn consume<R>(
        self,
        message: Message2,
        rng: &mut R,
        s_pk: &PublicKey,
    ) -> Result<(StateFinal, PublicKey, Message3), ()>
    where
        R: rand::Rng,
    {
        let Concat(Concat(mut encrypted_peer_s_pk, mut encrypted_e_ct), mut tag) = message;
        match self {
            StateEphemeral {
                symmetric_state,
                e_sk,
                e_pk,
            } => {
                let peer_s_pk_c;
                let peer_s_pk;
                let mut encrypted_peer_s_ct;
                let peer_s_ss;
                let mut encrypted_s_pk_lattice = Encrypted::new(s_pk.lattice.clone());

                let symmetric_state = symmetric_state
                    .decrypt(
                        encrypted_peer_s_pk.data.as_mut_slice(),
                        encrypted_peer_s_pk.tag,
                    )?
                    .decrypt(encrypted_e_ct.data.as_mut_slice(), encrypted_e_ct.tag)?
                    .mix_shared_secret({
                        peer_s_pk_c = encrypted_peer_s_pk.extract();
                        peer_s_pk = decompress(&peer_s_pk_c);
                        let peer_s_pq = peer_s_pk.lattice.encapsulate(rng);
                        encrypted_peer_s_ct = Encrypted::new(peer_s_pq.ct);
                        peer_s_ss = peer_s_pq.ss;
                        &Curve::compress(&peer_s_pk.elliptic.exp_ec(&e_sk.elliptic))
                    })
                    .mix_shared_secret({
                        PkLattice::decapsulate(&e_pk.lattice, &e_sk.lattice, &encrypted_e_ct.data)
                            .as_ref()
                    })
                    .decrypt(&mut [], tag)?
                    .encrypt(encrypted_peer_s_ct.data.as_mut())
                    .destruct(|t| encrypted_peer_s_ct.tag = t)
                    .encrypt(encrypted_s_pk_lattice.data.as_mut())
                    .destruct(|t| encrypted_s_pk_lattice.tag = t)
                    .mix_shared_secret(&peer_s_ss)
                    .encrypt(&mut [])
                    .destruct(|t| tag = t);

                Ok((
                    StateFinal {
                        symmetric_state: symmetric_state,
                    },
                    peer_s_pk,
                    Concat(Concat(encrypted_s_pk_lattice, encrypted_peer_s_ct), tag),
                ))
            },
        }
    }
}

impl StateFinal {
    pub fn generate<R, P, C>(
        self,
        message: Message3,
        rng: &mut R,
        payload: P,
        s_pk: &PublicKey,
        s_sk: &SecretKey,
        peer_s_pi: &PublicIdentity,
    ) -> Result<(Cipher<Noise, C>, PublicKey, Message4<P>), ()>
    where
        R: rand::Rng,
        C: Rotor<Noise>,
        P: Line,
        Encrypted<P>: Line,
    {
        let Concat(Concat(mut encrypted_peer_s_pk_lattice, mut encrypted_s_ct), tag) = message;
        match self {
            StateFinal { symmetric_state } => {
                let peer_s_pk_lattice;
                let mut encrypted_peer_s_ct;
                let peer_s_pq;
                let mut payload = Encrypted::new(payload);
                let cipher = symmetric_state
                    .decrypt(encrypted_s_ct.data.as_mut(), encrypted_s_ct.tag)?
                    .decrypt(
                        encrypted_peer_s_pk_lattice.data.as_mut(),
                        encrypted_peer_s_pk_lattice.tag,
                    )?
                    .mix_shared_secret({
                        PkLattice::decapsulate(
                            &s_pk.lattice,
                            &s_sk.lattice,
                            &encrypted_s_ct.extract(),
                        )
                        .as_ref()
                    })
                    .decrypt(&mut [], tag)?
                    .encrypt({
                        peer_s_pk_lattice = encrypted_peer_s_pk_lattice.extract();
                        peer_s_pq = peer_s_pk_lattice.encapsulate(rng);
                        encrypted_peer_s_ct = Encrypted::new(peer_s_pq.ct);
                        encrypted_peer_s_ct.data.as_mut()
                    })
                    .destruct(|t| encrypted_peer_s_ct.tag = t)
                    .mix_shared_secret(peer_s_pq.ss.as_ref())
                    .encrypt(payload.data.as_mut())
                    .destruct(|t| payload.tag = t)
                    .finish();

                let peer_s_pk = PublicKey {
                    elliptic: Curve::decompress(&peer_s_pi.elliptic)?,
                    lattice: peer_s_pk_lattice,
                };
                if peer_s_pi.ne(&PublicIdentity::new(&peer_s_pk)) {
                    return Err(());
                };
                Ok((cipher, peer_s_pk, Concat(encrypted_peer_s_ct, payload)))
            },
        }
    }

    pub fn consume<R, P>(
        self,
        message: Message4<P>,
        s_pk: &PublicKey,
        s_sk: &SecretKey,
    ) -> Result<(Cipher<Noise, R>, P), ()>
    where
        R: Rotor<Noise>,
        P: Line,
        Encrypted<P>: Line,
    {
        let Concat(mut encrypted_s_ct, mut payload) = message;
        match self {
            StateFinal { symmetric_state } => {
                let cipher = symmetric_state
                    .decrypt(encrypted_s_ct.data.as_mut(), encrypted_s_ct.tag)?
                    .mix_shared_secret({
                        PkLattice::decapsulate(
                            &s_pk.lattice,
                            &s_sk.lattice,
                            &encrypted_s_ct.extract(),
                        )
                        .as_ref()
                    })
                    .decrypt(payload.data.as_mut(), payload.tag)?
                    .finish()
                    .swap();

                Ok((cipher, payload.extract()))
            },
        }
    }
}

pub type SimpleRotor = PhantomData<Noise>;

pub type SimpleCipher = Cipher<Noise, SimpleRotor>;

pub type SimpleUnidirectional = Unidirectional<Noise, SimpleRotor>;

#[cfg(test)]
mod tests {
    use std::ops::Add;
    use rac::generic_array::{GenericArray, sequence::GenericSequence, typenum};
    use super::{SimpleRotor, State, PublicKey, PublicIdentity};

    #[test]
    fn handshake() {
        let mut rng = rand::thread_rng();

        let (i_sk, i_pk) = PublicKey::key_pair(&mut rng);
        let (r_sk, r_pk) = PublicKey::key_pair(&mut rng);
        let r_pi = PublicIdentity::new(&r_pk);

        // 1472
        type L1472 = <typenum::U1024 as Add<typenum::U348>>::Output;
        let orig_b = GenericArray::<u8, L1472>::generate(|_| rand::random());
        let payload = orig_b.clone();

        let i_state = State::new(&r_pi);
        let r_state = State::new(&r_pi);

        let (i_state, message) = i_state.generate(&mut rng, &r_pi).unwrap();
        let (r_state, message) = r_state.consume(message, &mut rng, &r_sk).unwrap();
        let (i_state, message) = i_state.generate(message, &mut rng, &i_sk, &i_pk).unwrap();
        let (r_state, _i_pk, message) = r_state.consume(message, &mut rng, &r_pk).unwrap();
        let (mut i_cipher, _r_pk, message) = i_state
            .generate::<_, _, SimpleRotor>(message, &mut rng, payload, &i_pk, &i_sk, &r_pi)
            .unwrap();
        let (mut r_cipher, payload) = r_state
            .consume::<SimpleRotor, _>(message, &r_pk, &r_sk)
            .unwrap();

        assert_eq!(orig_b, payload);
        //assert_eq!(i_pk, _i_pk.as_ref());
        //assert_eq!(r_pk, _r_pk.as_ref());

        for _ in 0..16 {
            let orig = rand::random::<[u8; 32]>();
            let mut a = orig.clone();
            let tag = r_cipher.encrypt(b"vru", a.as_mut());
            i_cipher.decrypt(b"vru", a.as_mut(), &tag).unwrap();
            assert_eq!(orig, a);
        }
    }
}
