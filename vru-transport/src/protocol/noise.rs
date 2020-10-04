use rac::{LineValid, Line, Curve, Concat};
use generic_array::{GenericArray, sequence::GenericSequence, typenum};

use vru_noise::{Cipher, SymmetricState, Key, Tag, ChainingKey};
use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};

use failure::Fail;
use std::marker::PhantomData;

mod pq {
    use rac::{LineValid, Line, Concat};
    use generic_array::{GenericArray, typenum};
    use pqcrypto_kyber::kyber768;
    use pqcrypto_traits::kem::{PublicKey as _, SharedSecret as _, Ciphertext as _};
    use pq_pseudorandom::{pack_kyber768, unpack_kyber768, KYBER768_PACKED_POLY_PADDING};

    pub struct PqPublicKey(kyber768::PublicKey);

    pub struct PqSecretKey(kyber768::SecretKey);

    pub type PqPublicKeyCompressed = Concat<GenericArray<u8, typenum::U1024>, GenericArray<u8, typenum::U132>>;
    pub type PqSharedSecret = GenericArray<u8, typenum::U32>;
    pub type PqCipherText = Concat<GenericArray<u8, typenum::U1024>, GenericArray<u8, typenum::U64>>;

    impl PqPublicKey {
        pub fn compress<R>(&self, rng: &mut R) -> PqPublicKeyCompressed
        where
            R: rand::Rng,
        {
            let padding = loop {
                let p = rng.gen();
                if p & 0b111111 < KYBER768_PACKED_POLY_PADDING {
                    break p;
                }
            };
            let mut d = GenericArray::default();
            d.as_mut_slice().clone_from_slice(pack_kyber768(self.0.as_bytes(), padding).as_ref());
            Concat::clone_array(&d)
        }

        pub fn decompress(c: &PqPublicKeyCompressed) -> Self {
            use std::convert::TryInto;

            let data = c.clone_line();
            let data = unpack_kyber768(data.as_ref().try_into().unwrap());
            PqPublicKey(kyber768::PublicKey::from_bytes(data.as_ref()).unwrap())
        }

        pub fn key_pair() -> (PqSecretKey, Self) {
            let (pk, sk) = kyber768::keypair();
            (PqSecretKey(sk), PqPublicKey(pk))
        }

        pub fn encapsulate(&self) -> (PqSharedSecret, PqCipherText) {
            let (ss, ct) = kyber768::encapsulate(&self.0);
            let mut d = GenericArray::default();
            d.as_mut_slice().clone_from_slice(ss.as_bytes());
            let ss = d;
            let mut d = GenericArray::default();
            d.as_mut_slice().clone_from_slice(ct.as_bytes());
            let ct = Concat::clone_array(&d);
            (ss, ct)
        }

        pub fn decapsulate(sk: &PqSecretKey, ct: &PqCipherText) -> PqSharedSecret {
            let ct = kyber768::Ciphertext::from_bytes(ct.clone_line().as_ref()).unwrap();
            let ss = kyber768::decapsulate(&ct, &sk.0);
            let mut d = GenericArray::default();
            d.as_mut_slice().clone_from_slice(ss.as_bytes());
            d
        }
    }
}
use self::pq::{PqPublicKeyCompressed, PqCipherText, PqPublicKey, PqSecretKey};

pub type Noise = (sha3::Sha3_512, byteorder::LittleEndian, chacha20poly1305::ChaCha20Poly1305);

pub type CipherM = Cipher<Noise, PhantomData<Noise>>;

pub type CompressedPoint = GenericArray<u8, <EdwardsPoint as Curve>::CompressedLength>;

pub type First = Concat<Concat<CompressedPoint, PqPublicKeyCompressed>, Tag<Noise>>;

pub type Second = Concat<Concat<CompressedPoint, PqCipherText>, Tag<Noise>>;

pub type Third = Concat<Concat<Concat<CompressedPoint, PqCipherText>, Tag<Noise>>, Tag<Noise>>;

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
    SymmetricState::new("Noise_XK_25519_Kyber_ChaChaPoly_SHA3/512")
        .mix_hash(b"vru")
        .mix_hash(&Curve::compress(pk))
}

pub fn generate_one<R>(
    rng: &mut R,
    state: SymmetricState<Noise, ChainingKey<Noise>>,
    peer_pk: &EdwardsPoint,
) -> ((Scalar, PqSecretKey), SymmetricState<Noise, Key<Noise, typenum::U1>>, First)
where
    R: rand::Rng,
{
    let (ephemeral, ephemeral_public) = key_pair(rng);
    let ephemeral_pk_compressed = Curve::compress(&ephemeral_public);
    let (pq_ephemeral, pq_ephemeral_public) = PqPublicKey::key_pair();
    let pq_ephemeral_pk_compressed = pq_ephemeral_public.compress(rng);

    let mut tag = GenericArray::default();

    let state = state
        .mix_hash(&ephemeral_pk_compressed)
        .mix_hash(&pq_ephemeral_pk_compressed.clone_line())
        .mix_shared_secret(&Curve::compress(&peer_pk.exp_ec(&ephemeral)))
        .encrypt(&mut [])
        .destruct(|t| tag = t);

    ((ephemeral, pq_ephemeral), state, Concat(Concat(ephemeral_pk_compressed, pq_ephemeral_pk_compressed), tag))
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
    let Concat(Concat(peer_ephemeral_pk_compressed, peer_pq_ephemeral_pk_compressed), mut tag) = msg;
    let peer_ephemeral_pk = EdwardsPoint::decompress(&peer_ephemeral_pk_compressed)
        .map_err(|()| HandshakeError::BadPk)?;
    let peer_pq_ephemeral_pk = PqPublicKey::decompress(&peer_pq_ephemeral_pk_compressed);
    let (pq_ephemeral_ss, pq_ephemeral_ct) = peer_pq_ephemeral_pk.encapsulate();

    let (ephemeral, ephemeral_public) = key_pair(rng);
    let ephemeral_pk_compressed = Curve::compress(&ephemeral_public);

    let state = state
        .mix_hash(&peer_ephemeral_pk_compressed)
        .mix_hash(&peer_pq_ephemeral_pk_compressed.clone_line())
        .mix_shared_secret(&Curve::compress(&peer_ephemeral_pk.exp_ec(&sk)))
        .decrypt(&mut [], tag)
        .map_err(|()| HandshakeError::BadMac)?
        .mix_hash(&ephemeral_pk_compressed)
        .mix_shared_secret(&Curve::compress(&peer_ephemeral_pk.exp_ec(&ephemeral)))
        .mix_shared_secret(&pq_ephemeral_ss)
        .encrypt(&mut [])
        .destruct(|t| tag = t);

    Ok((ephemeral, state, Concat(Concat(ephemeral_pk_compressed, pq_ephemeral_ct), tag)))
}

pub fn receive_two(
    state: SymmetricState<Noise, Key<Noise, typenum::U1>>,
    ephemeral: (Scalar, PqSecretKey),
    sk: &Scalar,
    peer_pq_pk: &PqPublicKey,
    msg: Second,
    payload: &mut [u8],
) -> Result<(CipherM, Third), HandshakeError> {
    let (ephemeral, pq_ephemeral) = ephemeral;

    let Concat(Concat(peer_ephemeral_pk_compressed, pq_ephemeral_ct), mut tag) = msg;
    let peer_ephemeral_pk = EdwardsPoint::decompress(&peer_ephemeral_pk_compressed)
        .map_err(|()| HandshakeError::BadPk)?;
    let pq_ephemeral_ss = PqPublicKey::decapsulate(&pq_ephemeral, &pq_ephemeral_ct);

    let this_pk = Curve::compress(&EdwardsPoint::base().exp_ec(&sk));
    let mut pk_tag = GenericArray::default();

    let (pq_ss, pq_ct) = peer_pq_pk.encapsulate();

    let mut to_encrypt = Concat(this_pk, pq_ct).clone_line();

    let cipher = state
        .mix_hash(&peer_ephemeral_pk_compressed)
        .mix_shared_secret(&Curve::compress(&peer_ephemeral_pk.exp_ec(&ephemeral)))
        .mix_shared_secret(&pq_ephemeral_ss)
        .decrypt(&mut [], tag)
        .map_err(|()| HandshakeError::BadMac)?
        .encrypt(to_encrypt.as_mut())
        .destruct(|t| pk_tag = t)
        .mix_shared_secret(&Curve::compress(&peer_ephemeral_pk.exp_ec(&sk)))
        .mix_shared_secret(&pq_ss)
        .encrypt(payload)
        .destruct(|t| tag = t)
        .finish();

    Ok((cipher, Concat(Concat(Concat::clone_array(&to_encrypt), pk_tag), tag)))
}

pub fn receive_three(
    state: SymmetricState<Noise, Key<Noise, typenum::U1>>,
    ephemeral: Scalar,
    pq_sk: &PqSecretKey,
    msg: Third,
    payload: &mut [u8],
) -> Result<(CipherM, EdwardsPoint), HandshakeError> {
    let Concat(Concat(Concat(peer_ephemeral_pk_compressed_encrypted, pq_ct_encrypted), pk_tag), tag) = msg;
    let peer_pk;
    let peer_ephemeral_pk_compressed_pq_ct: Concat<_, PqCipherText>;

    let mut to_decrypt = Concat(peer_ephemeral_pk_compressed_encrypted, pq_ct_encrypted).clone_line();
    let cipher = state
        .decrypt(to_decrypt.as_mut(), pk_tag)
        .map_err(|()| HandshakeError::BadMac)?
        .mix_shared_secret({
            peer_ephemeral_pk_compressed_pq_ct = Concat::clone_array(&to_decrypt);
            peer_pk = EdwardsPoint::decompress(&peer_ephemeral_pk_compressed_pq_ct.0)
                .map_err(|()| HandshakeError::BadPk)?;
            &Curve::compress(&peer_pk.exp_ec(&ephemeral))
        })
        .mix_shared_secret({
            let pq_ss = PqPublicKey::decapsulate(pq_sk, &peer_ephemeral_pk_compressed_pq_ct.1);
            pq_ss.clone_line().as_ref()
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
        let (r_pq_sk, r_pq_pk) = PqPublicKey::key_pair();

        let i_state = initiate(&r_pk);
        let r_state = initiate(&r_pk);

        let (ie, i_state, first) = 
            generate_one(&mut rng, i_state, &r_pk);

        let (re, r_state, second) =
            generate_two(&mut rng, r_state, &r_sk, first).unwrap();

        let orig = rand::random::<[u8; 32]>();
        let mut a = orig.clone();

        let (mut i_cipher, third) =
            receive_two(i_state, ie, &i_sk, &r_pq_pk, second, a.as_mut()).unwrap();

        let (mut r_cipher, pk) =
            receive_three(r_state, re, &r_pq_sk, third, a.as_mut()).unwrap();

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
