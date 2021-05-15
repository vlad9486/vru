use vru_noise::{SymmetricState, MacMismatch, ChainingKey, Key, Cipher, Rotor};
use rac::{Array, Concat, LineValid, Line, generic_array::typenum};
use thiserror::Error;
use super::{
    key::{Identity, PublicKey, PublicKeyBytes, SecretKey, Ct},
    noise::{Noise, EncryptedDefault, SymmetricStateOps},
};

// PublicKey = 1120
// Ct = 1152

// 1120
pub type Message0 = PublicKeyBytes;

// (1152 + p + 16) + 1120 + (1120 + 16)
pub type Message1<P> = (
    Concat<Ct, EncryptedDefault<P>>,
    PublicKeyBytes,
    EncryptedDefault<PublicKeyBytes>,
);

// (1152 + p + 16) + 1152 + (1120 + 16)
pub type Message2<Q, R> = (
    Concat<Ct, EncryptedDefault<Q>>,
    Ct,
    Concat<EncryptedDefault<PublicKeyBytes>, EncryptedDefault<R>>,
);

// (1152 + p + 16)
pub type Message3<S> = Concat<Ct, EncryptedDefault<S>>;

pub struct InitiatorsEphemeral {
    symmetric_state: SymmetricState<Noise, ChainingKey<Noise>>,
    e_pk: PublicKey,
    e_sk: SecretKey,
}

pub struct RespondersEphemeral {
    symmetric_state: SymmetricState<Noise, Key<Noise, typenum::U0>>,
    e_pk: PublicKey,
    e_sk: SecretKey,
}

pub struct InitiatorsFinal {
    symmetric_state: SymmetricState<Noise, Key<Noise, typenum::U1>>,
}

#[derive(Debug, Error)]
pub enum InitiatorsError {
    #[error("payload_p {}", _0)]
    PayloadPMac(MacMismatch),
    #[error("payload_s {}", _0)]
    PayloadSMac(MacMismatch),
    #[error("static key {}", _0)]
    StaticKeyMac(MacMismatch),
}

#[derive(Debug, Error)]
pub enum RespondersError {
    #[error("payload_q {}", _0)]
    PayloadQMac(MacMismatch),
    #[error("payload_r {}", _0)]
    PayloadRMac(MacMismatch),
    #[error("static key {}", _0)]
    StaticKeyMac(MacMismatch),
}

// the handshake variant is xx, but the initiator know responder pk
// the hash of pk is mixed in the state at the beginning
// so parties are able to detect a man in the middle

// -> e
// <- ec, (p), e, ee, s, es
// -> ec, (q), sc, s, se, (r)
// <- sc, (s)

pub fn out0(seed: &Array<typenum::U96>, peer_s_pi: &Identity) -> (InitiatorsEphemeral, Message0) {
    let (e_pk, e_sk) = PublicKey::gen(seed);
    let e_pkc = e_pk.compress();
    let symmetric_state = SymmetricState::<Noise, _>::new("Noise_XX_25519+Kyber_ChaChaPoly_SHA256")
        .mix_hash(&peer_s_pi.as_ref())
        .mix_hash(&e_pkc.clone_line());

    (
        InitiatorsEphemeral {
            symmetric_state,
            e_pk,
            e_sk,
        },
        e_pkc,
    )
}

pub fn take1_out2<P, Q, R>(
    seed: &Concat<Array<typenum::U32>, Array<typenum::U32>>,
    state: InitiatorsEphemeral,
    s_pk: &PublicKey,
    s_sk: &SecretKey,
    message: Message1<P>,
    payload_q: Q,
    payload_r: R,
) -> Result<(InitiatorsFinal, PublicKey, P, Message2<Q, R>), InitiatorsError>
where
    P: Line,
    EncryptedDefault<P>: Line,
    Q: Line,
    EncryptedDefault<Q>: Line,
    R: Line,
    EncryptedDefault<R>: Line,
    EncryptedDefault<PublicKeyBytes>: Line,
{
    let (Concat(peer_e_ct, payload_p), peer_e_pkc, enc_peer_s_pkc) = message;
    let InitiatorsEphemeral {
        symmetric_state,
        e_pk,
        e_sk,
    } = state;

    let (symmetric_state, payload_p) = symmetric_state
        .mix_shared_secret(&e_pk.decapsulate(&e_sk, &peer_e_ct))
        .decrypt_line(payload_p)
        .map_err(InitiatorsError::PayloadPMac)?;
    let symmetric_state = symmetric_state.mix_hash(&peer_e_pkc.clone_line());
    let peer_e_pk = PublicKey::decompress(peer_e_pkc);
    let (symmetric_state, peer_s_pkc) = symmetric_state
        .mix_shared_secret(&peer_e_pk.dh(&e_sk))
        .decrypt_line(enc_peer_s_pkc)
        .map_err(InitiatorsError::StaticKeyMac)?;
    let peer_s_pk = PublicKey::decompress(peer_s_pkc);
    let peer_e_pq;
    let symmetric_state = symmetric_state
        .mix_shared_secret(&peer_s_pk.dh(&e_sk))
        .mix_shared_secret({
            peer_e_pq = peer_e_pk.encapsulate(&seed.0);
            &peer_e_pq.ss
        });
    let (symmetric_state, payload_q) = symmetric_state.encrypt_line(payload_q);
    let peer_s_pq;
    let s_pkc = s_pk.compress();
    let (symmetric_state, enc_s_pkc) = symmetric_state
        .mix_shared_secret({
            peer_s_pq = peer_s_pk.encapsulate(&seed.1);
            &peer_s_pq.ss
        })
        .encrypt_line(s_pkc);
    let (symmetric_state, payload_r) = symmetric_state
        .mix_shared_secret(&peer_e_pk.dh(&s_sk))
        .encrypt_line(payload_r);

    Ok((
        InitiatorsFinal { symmetric_state },
        peer_s_pk,
        payload_p,
        (
            Concat(peer_e_pq.ct, payload_q),
            peer_s_pq.ct,
            Concat(enc_s_pkc, payload_r),
        ),
    ))
}

pub fn take_3<S, Z>(
    state: InitiatorsFinal,
    s_pk: &PublicKey,
    s_sk: &SecretKey,
    message: Message3<S>,
) -> Result<(Cipher<Noise, Z>, Array<typenum::U32>, S), InitiatorsError>
where
    S: Line,
    EncryptedDefault<S>: Line,
    Z: Rotor<Noise>,
{
    let Concat(peer_s_ct, payload_s) = message;
    let InitiatorsFinal { symmetric_state } = state;

    let (symmetric_state, payload_s) = symmetric_state
        .mix_shared_secret(&s_pk.decapsulate(&s_sk, &peer_s_ct))
        .decrypt_line(payload_s)
        .map_err(InitiatorsError::PayloadSMac)?;
    let (cipher, hash) = symmetric_state.finish();

    Ok((cipher, hash, payload_s))
}

////////////

pub fn take0_out1<P>(
    seed: &Concat<Array<typenum::U96>, Array<typenum::U32>>,
    s_pi: &Identity,
    s_pk: &PublicKey,
    s_sk: &SecretKey,
    message: Message0,
    payload_p: P,
) -> (RespondersEphemeral, Message1<P>)
where
    P: Line,
    EncryptedDefault<P>: Line,
    EncryptedDefault<PublicKeyBytes>: Line,
{
    let peer_e_pkc = message;

    let symmetric_state = SymmetricState::<Noise, _>::new("Noise_XX_25519+Kyber_ChaChaPoly_SHA256")
        .mix_hash(&s_pi.as_ref())
        .mix_hash(&peer_e_pkc.clone_line());
    let peer_e_pk = PublicKey::decompress(peer_e_pkc);
    let peer_e_pq;
    let (symmetric_state, payload_p) = symmetric_state
        .mix_shared_secret({
            peer_e_pq = peer_e_pk.encapsulate(&seed.1);
            &peer_e_pq.ss
        })
        .encrypt_line(payload_p);
    let (e_pk, e_sk) = PublicKey::gen(&seed.0);
    let e_pkc = e_pk.compress();
    let s_pkc = s_pk.compress();
    let (symmetric_state, enc_s_pkc) = symmetric_state
        .mix_hash(&e_pkc.clone_line())
        .mix_shared_secret(&peer_e_pk.dh(&e_sk))
        .encrypt_line(s_pkc);
    let symmetric_state = symmetric_state.mix_shared_secret(&peer_e_pk.dh(&s_sk));

    (
        RespondersEphemeral {
            symmetric_state,
            e_sk,
            e_pk,
        },
        (Concat(peer_e_pq.ct, payload_p), e_pkc, enc_s_pkc),
    )
}

#[rustfmt::skip]
pub fn take2_out3<Q, R, S, Z>(
    seed: &Array<typenum::U32>,
    state: RespondersEphemeral,
    s_pk: &PublicKey,
    s_sk: &SecretKey,
    message: Message2<Q, R>,
    payload_s: S,
) -> Result<(Cipher<Noise, Z>, Array<typenum::U32>, PublicKey, Q, R, Message3<S>), RespondersError>
where
    Q: Line,
    EncryptedDefault<Q>: Line,
    R: Line,
    EncryptedDefault<R>: Line,
    S: Line,
    EncryptedDefault<S>: Line,
    EncryptedDefault<PublicKeyBytes>: Line,
    Z: Rotor<Noise>,
{
    let (Concat(peer_e_ct, payload_q), peer_s_ct, Concat(enc_peer_s_pkc, payload_r)) = message;
    let RespondersEphemeral {
        symmetric_state,
        e_pk,
        e_sk,
    } = state;

    let (symmetric_state, payload_q) = symmetric_state
        .mix_shared_secret(&e_pk.decapsulate(&e_sk, &peer_e_ct))
        .decrypt_line(payload_q)
        .map_err(RespondersError::PayloadQMac)?;
    let (symmetric_state, peer_s_pkc) = symmetric_state
        .mix_shared_secret(&s_pk.decapsulate(&s_sk, &peer_s_ct))
        .decrypt_line(enc_peer_s_pkc)
        .map_err(RespondersError::StaticKeyMac)?;
    let peer_s_pk = PublicKey::decompress(peer_s_pkc);
    let (symmetric_state, payload_r) = symmetric_state
        .mix_shared_secret(&peer_s_pk.dh(&e_sk))
        .decrypt_line(payload_r)
        .map_err(RespondersError::PayloadRMac)?;
    let peer_s_pq;
    let (symmetric_state, payload_s) = symmetric_state
        .mix_shared_secret({
            peer_s_pq = peer_s_pk.encapsulate(&seed);
            &peer_s_pq.ss
        })
        .encrypt_line(payload_s);
    let (cipher, hash) = symmetric_state.finish();

    Ok((
        cipher.swap(),
        hash,
        peer_s_pk,
        payload_q,
        payload_r,
        Concat(peer_s_pq.ct, payload_s),
    ))
}
