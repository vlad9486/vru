use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::PublicKey as _;
use pq_pseudorandom::{pack_kyber768, unpack_kyber768, KYBER768_PACKED_SIZE, KYBER768_PACKED_POLY_PADDING};

type First = [u8; KYBER768_PACKED_SIZE];

pub fn generate_one<R>(rng: &mut R) -> (First, kyber768::SecretKey)
where
    R: rand::Rng,
{
    let (eps, esk) = kyber768::keypair();
    let padding = loop {
        let p = rng.gen();
        if p & 0b111111 < KYBER768_PACKED_POLY_PADDING {
            break p;
        }
    };
    (pack_kyber768(eps.as_bytes(), padding), esk)
}

pub fn generate_two(msg: First) {

}
