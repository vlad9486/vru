use rac::{LineValid, Curve, Concat};
use generic_array::{GenericArray, sequence::GenericSequence, typenum};

use vru_noise::{Cipher, SymmetricState, Key, Tag, ChainingKey};
use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};

use failure::Fail;
use std::marker::PhantomData;

pub type Noise = (sha3::Sha3_512, byteorder::LittleEndian, chacha20poly1305::ChaCha20Poly1305);

pub type CipherM = Cipher<Noise, PhantomData<Noise>>;

pub type CompressedPoint = GenericArray<u8, <EdwardsPoint as Curve>::CompressedLength>;

pub type First = Concat<CompressedPoint, Tag<Noise>>;

pub type Second = Concat<CompressedPoint, Tag<Noise>>;

pub type Third = Concat<Concat<CompressedPoint, Tag<Noise>>, Tag<Noise>>;

pub fn key_pair<R>(rng: &mut R) -> (Scalar, EdwardsPoint)
where
    R: rand::Rng,
{
    let sk = Scalar::try_clone_array(&GenericArray::generate(|_| rng.gen())).unwrap();
    let pk = EdwardsPoint::base().exp_ec(&sk);
    (sk, pk)
}

#[derive(Debug, Fail)]
pub enum HandshakeError {
    #[fail(display = "Bad public key")]
    BadPk,
    #[fail(display = "Bad message authentication code")]
    BadMac,
}

pub fn initiate(pk: &EdwardsPoint) -> SymmetricState<Noise, ChainingKey<Noise>> {
    SymmetricState::new("Noise_XK_25519_ChaChaPoly_SHA3/512")
        .mix_hash(b"vru")
        .mix_hash(&Curve::compress(pk))
}

pub fn generate_one<R>(
    rng: &mut R,
    state: SymmetricState<Noise, ChainingKey<Noise>>,
    peer_pk: &EdwardsPoint,
) -> (Scalar, SymmetricState<Noise, Key<Noise, typenum::U1>>, First)
where
    R: rand::Rng,
{
    let (ephemeral, ephemeral_public) = key_pair(rng);
    let ephemeral_pk_compressed = Curve::compress(&ephemeral_public);
    let mut tag = GenericArray::default();

    let state = state
        .mix_hash(&ephemeral_pk_compressed)
        .mix_shared_secret(&Curve::compress(&peer_pk.exp_ec(&ephemeral)))
        .encrypt(&mut [])
        .destruct(|t| tag = t);

    (ephemeral, state, Concat(ephemeral_pk_compressed, tag))
}

pub fn generate_two<R>(
    rng: &mut R,
    state: SymmetricState<Noise, ChainingKey<Noise>>,
    sk: &Scalar,
    msg: First,
) -> Result<(Scalar, SymmetricState<Noise, Key<Noise, typenum::U1>>, Second), HandshakeError>
where
    R: rand::Rng,
{
    let Concat(peer_ephemeral_pk_compressed, mut tag) = msg;
    let peer_ephemeral_pk = EdwardsPoint::decompress(&peer_ephemeral_pk_compressed)
        .map_err(|()| HandshakeError::BadPk)?;

    let (ephemeral, ephemeral_public) = key_pair(rng);
    let ephemeral_pk_compressed = Curve::compress(&ephemeral_public);

    let state = state
        .mix_hash(&peer_ephemeral_pk_compressed)
        .mix_shared_secret(&Curve::compress(&peer_ephemeral_pk.exp_ec(&sk)))
        .decrypt(&mut [], tag)
        .map_err(|()| HandshakeError::BadMac)?
        .mix_hash(&ephemeral_pk_compressed)
        .mix_shared_secret(&Curve::compress(&peer_ephemeral_pk.exp_ec(&ephemeral)))
        .encrypt(&mut [])
        .destruct(|t| tag = t);

    Ok((ephemeral, state, Concat(ephemeral_pk_compressed, tag)))
}

pub fn receive_two(
    state: SymmetricState<Noise, Key<Noise, typenum::U1>>,
    ephemeral: Scalar,
    sk: &Scalar,
    msg: Second,
    payload: &mut [u8],
) -> Result<(CipherM, Third), HandshakeError> {
    let Concat(peer_ephemeral_pk_compressed, mut tag) = msg;
    let peer_ephemeral_pk = EdwardsPoint::decompress(&peer_ephemeral_pk_compressed)
        .map_err(|()| HandshakeError::BadPk)?;

    let mut this_pk = Curve::compress(&EdwardsPoint::base().exp_ec(&sk));
    let mut pk_tag = GenericArray::default();

    let cipher = state
        .mix_hash(&peer_ephemeral_pk_compressed)
        .mix_shared_secret(&Curve::compress(&peer_ephemeral_pk.exp_ec(&ephemeral)))
        .decrypt(&mut [], tag)
        .map_err(|()| HandshakeError::BadMac)?
        .encrypt(this_pk.as_mut())
        .destruct(|t| pk_tag = t)
        .mix_shared_secret(&Curve::compress(&peer_ephemeral_pk.exp_ec(&sk)))
        .encrypt(payload)
        .destruct(|t| tag = t)
        .finish();

    Ok((cipher, Concat(Concat(this_pk, pk_tag), tag)))
}

pub fn receive_three(
    state: SymmetricState<Noise, Key<Noise, typenum::U1>>,
    ephemeral: Scalar,
    msg: Third,
    payload: &mut [u8],
) -> Result<(CipherM, EdwardsPoint), HandshakeError> {
    let Concat(Concat(mut peer_ephemeral_pk_compressed, pk_tag), tag) = msg;
    let peer_pk;

    let cipher = state
        .decrypt(peer_ephemeral_pk_compressed.as_mut(), pk_tag)
        .map_err(|()| HandshakeError::BadMac)?
        .mix_shared_secret({
            peer_pk = EdwardsPoint::decompress(&peer_ephemeral_pk_compressed)
                .map_err(|()| HandshakeError::BadPk)?;
            &Curve::compress(&peer_pk.exp_ec(&ephemeral))
        })
        .decrypt(payload, tag)
        .map_err(|()| HandshakeError::BadMac)?
        .finish()
        .swap();

    Ok((cipher, peer_pk))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake() {
        let mut rng = rand::thread_rng();
        
        let (i_sk, i_pk) = key_pair(&mut rng);
        let (r_sk, r_pk) = key_pair(&mut rng);

        let i_state = initiate(&r_pk);
        let r_state = initiate(&r_pk);

        let (ie, i_state, first) = 
            generate_one(&mut rng, i_state, &r_pk);

        let (re, r_state, second) =
            generate_two(&mut rng, r_state, &r_sk, first).unwrap();

        let orig = rand::random::<[u8; 32]>();
        let mut a = orig.clone();

        let (mut i_cipher, third) =
            receive_two(i_state, ie, &i_sk, second, a.as_mut()).unwrap();

        let (mut r_cipher, pk) =
            receive_three(r_state, re, third, a.as_mut()).unwrap();

        assert_eq!(orig, a);

        assert_eq!(i_pk, pk);

        for _ in 0..16 {
            let orig = rand::random::<[u8; 32]>();
            let mut a = orig.clone();
            let tag = r_cipher.encrypt(b"vru", a.as_mut());
            i_cipher.decrypt(b"vru", a.as_mut(), &tag).unwrap();
            assert_eq!(orig, a);
        }
    }
}
