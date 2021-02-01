use curve25519_dalek::edwards::EdwardsPoint;
use vru_noise::{SymmetricState, Cipher, Rotor, ChainingKey, Key, Tag};
use rac::{Array, Concat, Curve, Line, LineValid, generic_array::typenum};

use super::lattice::{PkLattice, PkLatticeCompressed, CipherText};
use super::key::{SecretKey, PublicKey, PublicKeyCompressed, PublicIdentity};
use super::ops::{Noise, Encrypted, SymmetricStateOps};

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

pub type E<L> = Encrypted<Noise, L>;

// generate: State -> StateI, Message0
// 1136 = 1120 + 16
pub type Message0 = Concat<PublicKeyCompressed, Tag<Noise>>;
// consume: State, Message0 -> StateI, Message1
// 2288 = 1120 + 1152 + 16
pub type Message1 = Concat<Concat<PublicKeyCompressed, CipherText>, Tag<Noise>>;
// generate: StateI, Message1 -> StateF, Message2
// 2320 = 1120 + 16 + 1152 + 16 + 16
pub type Message2 = Concat<Concat<E<PublicKeyCompressed>, E<CipherText>>, Tag<Noise>>;
// consume: StateI, Message2 -> StateF, Message3, PublicKey
// 2288 = 1088 + 16 + 1152 + 16 + 16
pub type Message3 = Concat<Concat<E<PkLatticeCompressed>, E<CipherText>>, Tag<Noise>>;
// generate: StateF, Message3 -> Cipher, Message4
// 1184 = 1152 + 16 + 16
pub type Message4<P> = Concat<E<CipherText>, E<P>>;
// consume: StateF, Message2 -> Cipher

impl State {
    pub fn new(s_pi: &PublicIdentity) -> Self {
        State {
            symmetric_state: SymmetricState::new("Noise_XK_25519+Kyber_ChaChaPoly_SHA256")
                .mix_hash(b"vru")
                .mix_hash(&s_pi.elliptic)
                .mix_hash(&s_pi.lattice),
        }
    }

    pub fn generate(
        self,
        seed: &Array<typenum::U96>,
        peer_s_pi: &PublicIdentity,
    ) -> Result<(StateEphemeral, Message0), ()> {
        match self {
            State { symmetric_state } => {
                let (e_sk, e_pk) = PublicKey::key_pair_seed(seed);
                let e_pk_elliptic_c = Curve::compress(&e_pk.elliptic);
                let e_pk_lattice_c = e_pk.lattice.compress();
                let peer_s_pk_elliptic: EdwardsPoint = Curve::decompress(&peer_s_pi.elliptic)?;
                let mut tag = Array::default();

                let symmetric_state = symmetric_state
                    .mix_hash(&e_pk_elliptic_c)
                    .mix_hash(&e_pk_lattice_c)
                    .mix_shared_secret(&Curve::compress(&peer_s_pk_elliptic.exp_ec(&e_sk.elliptic)))
                    .encrypt(&mut [])
                    .destruct(|t| tag = t);

                Ok((
                    StateEphemeral {
                        symmetric_state: symmetric_state,
                        e_sk: e_sk,
                        e_pk: e_pk,
                    },
                    Concat(Concat(e_pk_elliptic_c, e_pk_lattice_c), tag),
                ))
            },
        }
    }

    pub fn consume(
        self,
        message: Message0,
        seed: &Concat<Array<typenum::U96>, Array<typenum::U32>>,
        s_sk: &SecretKey,
    ) -> Result<(StateEphemeral, Message1), ()> {
        let Concat(Concat(peer_e_pk_elliptic_c, peer_e_pk_lattice_c), mut tag) = message;
        match self {
            State { symmetric_state } => {
                let peer_e_pk = PublicKey {
                    elliptic: Curve::decompress(&peer_e_pk_elliptic_c).unwrap(),
                    lattice: PkLattice::decompress(&peer_e_pk_lattice_c),
                };
                let peer_e_pq = peer_e_pk.lattice.encapsulate(&seed.1);

                let (e_sk, e_pk) = PublicKey::key_pair_seed(&seed.0);
                let e_pk_elliptic_c = Curve::compress(&e_pk.elliptic);
                let e_pk_lattice_c = e_pk.lattice.compress();

                let symmetric_state = symmetric_state
                    .mix_hash(&peer_e_pk_elliptic_c)
                    .mix_hash(&peer_e_pk_lattice_c)
                    .mix_shared_secret(&Curve::compress(&peer_e_pk.elliptic.exp_ec(&s_sk.elliptic)))
                    .decrypt(&mut [], tag)?
                    .mix_hash(&e_pk_elliptic_c)
                    .mix_hash(&e_pk_lattice_c)
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
                    Concat(
                        Concat(Concat(e_pk_elliptic_c, e_pk_lattice_c), peer_e_pq.ct),
                        tag,
                    ),
                ))
            },
        }
    }
}

impl StateEphemeral {
    pub fn generate(
        self,
        message: Message1,
        seed: &Array<typenum::U32>,
        s_sk: &SecretKey,
        s_pk: &PublicKey,
    ) -> Result<(StateFinal, Message2), ()> {
        let Concat(Concat(Concat(peer_e_pk_elliptic_c, peer_e_pk_lattice_c), e_ct), mut tag) =
            message;
        match self {
            StateEphemeral {
                symmetric_state,
                e_sk,
                e_pk,
            } => {
                let peer_e_pk = PublicKey {
                    elliptic: Curve::decompress(&peer_e_pk_elliptic_c).unwrap(),
                    lattice: PkLattice::decompress(&peer_e_pk_lattice_c),
                };
                let e_ss = e_pk.lattice.decapsulate(&e_sk.lattice, &e_ct);
                let peer_e_pq = peer_e_pk.lattice.encapsulate(seed);
                let s_pk_c = Concat(Curve::compress(&s_pk.elliptic), s_pk.lattice.compress());

                let (symmetric_state, encrypted_s_pk) = symmetric_state
                    .mix_hash(&peer_e_pk_elliptic_c)
                    .mix_hash(&peer_e_pk_lattice_c)
                    .mix_shared_secret(&Curve::compress(&peer_e_pk.elliptic.exp_ec(&e_sk.elliptic)))
                    .mix_shared_secret(&e_ss)
                    .decrypt(&mut [], tag)?
                    .encrypt_line(s_pk_c.clone_line());
                let (symmetric_state, encrypted_peer_e_ct) =
                    symmetric_state.encrypt_line(peer_e_pq.ct);
                let symmetric_state = symmetric_state
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

    pub fn consume(
        self,
        message: Message2,
        seed: &Array<typenum::U32>,
        s_pk: &PublicKey,
    ) -> Result<(StateFinal, PublicKey, Message3), ()> {
        let Concat(Concat(encrypted_peer_s_pk, encrypted_e_ct), mut tag) = message;
        match self {
            StateEphemeral {
                symmetric_state,
                e_sk,
                e_pk,
            } => {
                let peer_s_pk;
                let peer_s_ss;
                let peer_s_pq;

                let (symmetric_state, Concat(peer_s_pk_elliptic_c, peer_s_pk_lattice_c)) =
                    symmetric_state.decrypt_line(encrypted_peer_s_pk)?;
                let (symmetric_state, peer_e_ct) = symmetric_state.decrypt_line(encrypted_e_ct)?;
                let (symmetric_state, encrypted_peer_s_ct) = symmetric_state
                    .mix_shared_secret({
                        peer_s_pk = PublicKey {
                            elliptic: Curve::decompress(&peer_s_pk_elliptic_c).unwrap(),
                            lattice: PkLattice::decompress(&peer_s_pk_lattice_c),
                        };
                        peer_s_pq = peer_s_pk.lattice.encapsulate(seed);
                        peer_s_ss = peer_s_pq.ss;
                        &Curve::compress(&peer_s_pk.elliptic.exp_ec(&e_sk.elliptic))
                    })
                    .mix_shared_secret(&e_pk.lattice.decapsulate(&e_sk.lattice, &peer_e_ct))
                    .decrypt(&mut [], tag)?
                    .encrypt_line(peer_s_pq.ct);
                let (symmetric_state, encrypted_s_pk_lattice) =
                    symmetric_state.encrypt_line(s_pk.lattice.compress());
                let symmetric_state = symmetric_state
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
    pub fn generate<P, R>(
        self,
        message: Message3,
        seed: &Array<typenum::U32>,
        payload: P,
        s_pk: &PublicKey,
        s_sk: &SecretKey,
        peer_s_pi: &PublicIdentity,
    ) -> Result<(Cipher<Noise, R>, Array<typenum::U32>, PublicKey, Message4<P>), ()>
    where
        R: Rotor<Noise>,
        P: Line,
        E<P>: Line,
    {
        let Concat(Concat(encrypted_peer_s_pk_lattice, encrypted_s_ct), tag) = message;
        match self {
            StateFinal { symmetric_state } => {
                let peer_s_pq;
                let peer_s_pk_lattice;

                let (symmetric_state, peer_s_ct) =
                    symmetric_state.decrypt_line::<CipherText>(encrypted_s_ct)?;
                let (symmetric_state, peer_s_pk_lattice_c) = symmetric_state
                    .decrypt_line::<PkLatticeCompressed>(encrypted_peer_s_pk_lattice)?;
                let (symmetric_state, encrypted_peer_s_ct) = symmetric_state
                    .mix_shared_secret(&s_pk.lattice.decapsulate(&s_sk.lattice, &peer_s_ct))
                    .decrypt(&mut [], tag)?
                    .encrypt_line::<CipherText>({
                        peer_s_pk_lattice = PkLattice::decompress(&peer_s_pk_lattice_c);
                        peer_s_pq = peer_s_pk_lattice.encapsulate(seed);
                        peer_s_pq.ct
                    });
                let (symmetric_state, encrypted_payload) = symmetric_state
                    .mix_shared_secret(&peer_s_pq.ss)
                    .encrypt_line(payload);
                let (cipher, hash) = symmetric_state.finish();

                let peer_s_pk = PublicKey {
                    elliptic: Curve::decompress(&peer_s_pi.elliptic)?,
                    lattice: peer_s_pk_lattice,
                };
                if peer_s_pi.ne(&PublicIdentity::new(&peer_s_pk)) {
                    return Err(());
                };
                Ok((
                    cipher,
                    hash,
                    peer_s_pk,
                    Concat(encrypted_peer_s_ct, encrypted_payload),
                ))
            },
        }
    }

    pub fn consume<R, P>(
        self,
        message: Message4<P>,
        s_pk: &PublicKey,
        s_sk: &SecretKey,
    ) -> Result<(Cipher<Noise, R>, Array<typenum::U32>, P), ()>
    where
        R: Rotor<Noise>,
        P: Line,
        E<P>: Line,
    {
        let Concat(encrypted_s_ct, encrypted_payload) = message;
        match self {
            StateFinal { symmetric_state } => {
                let (symmetric_state, s_ct) =
                    symmetric_state.decrypt_line::<CipherText>(encrypted_s_ct)?;
                let (symmetric_state, payload) = symmetric_state
                    .mix_shared_secret(&s_pk.lattice.decapsulate(&s_sk.lattice, &s_ct))
                    .decrypt_line(encrypted_payload)?;
                let (cipher, hash) = symmetric_state.finish();

                Ok((cipher.swap(), hash, P::clone_array(&payload)))
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Add;
    use rac::{
        Array, Concat, Line,
        generic_array::{sequence::GenericSequence, typenum},
    };
    use super::{State, PublicKey, PublicIdentity};
    use super::super::ops::TrivialCipher;

    #[test]
    fn handshake() {
        let Concat(Concat(i_s_seed, i_e_seed), Concat(i_pq_s_seed, i_pq_e_seed)) =
            Line::clone_array(&Array::<typenum::U256>::generate(|_| 0x12));
        let Concat(Concat(r_s_seed, r_e_seed), Concat(r_pq_s_seed, r_pq_e_seed)) =
            Line::clone_array(&Array::<typenum::U256>::generate(|_| 0x21));

        let (i_sk, i_pk) = PublicKey::key_pair_seed(&i_s_seed);
        let (r_sk, r_pk) = PublicKey::key_pair_seed(&r_s_seed);
        let r_pi = PublicIdentity::new(&r_pk);

        // 1472
        type L1472 = <typenum::U1024 as Add<typenum::U348>>::Output;
        let orig_b = Array::<L1472>::generate(|_| 0x33);
        let payload = orig_b.clone();

        let i_state = State::new(&r_pi);
        let r_state = State::new(&r_pi);

        let (i_state, message) = i_state.generate(&i_e_seed, &r_pi).unwrap();
        let (r_state, message) = r_state
            .consume(message, &Concat(r_pq_e_seed, r_e_seed), &r_sk)
            .unwrap();
        let (i_state, message) = i_state
            .generate(message, &i_pq_e_seed, &i_sk, &i_pk)
            .unwrap();
        let (r_state, _i_pk, message) = r_state.consume(message, &r_pq_s_seed, &r_pk).unwrap();
        let (mut i_cipher, i_hash, _r_pk, message): (TrivialCipher, _, _, _) = i_state
            .generate(message, &i_pq_s_seed, payload, &i_pk, &i_sk, &r_pi)
            .unwrap();
        let (mut r_cipher, r_hash, payload): (TrivialCipher, _, _) =
            r_state.consume(message, &r_pk, &r_sk).unwrap();

        let reference_hash = "c0d85b813261ab1965a4585687b3fa9d596e389d5cad17eb4752f31a76484b9e";
        assert_eq!(reference_hash, hex::encode(&i_hash));
        assert_eq!(reference_hash, hex::encode(&r_hash));

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
