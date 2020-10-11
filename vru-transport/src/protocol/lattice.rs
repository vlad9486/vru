use std::{convert::TryFrom, ops::Add};
use generic_array::{GenericArray, typenum};
use num_traits::ToPrimitive;
use num_bigint::{ToBigUint, BigUint};
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{PublicKey as _, SharedSecret as _, Ciphertext as _};

const KYBER_Q: u16 = 3329;

// 1124 * 8 - log2(53 * 3329 ^ 768) < 0.0014963977155275644
const KYBER768_PACKED_POLY_PADDING: u16 = 53;
const KYBER768_PACKED_POLY_SIZE: usize = 1124;
const KYBER768_PACKED_SIZE: usize = KYBER768_PACKED_POLY_SIZE + 32;

fn pack_kyber768(pk: &[u8], padding: u16) -> [u8; KYBER768_PACKED_SIZE] {
    assert!(pk.len() == 768 / 2 * 3 + 32);

    let mut i = 0u8.to_biguint().unwrap();
    for t in pk[..(768 / 2 * 3)].chunks(3) {
        let c0 = t[0] as u16 | (((t[1] & 0x0f) as u16) << 8);
        let c1 = (t[1] >> 4) as u16 | ((t[2] as u16) << 4);
        assert!(c0 < KYBER_Q && c1 < KYBER_Q);
        i *= KYBER_Q;
        i += c0;
        i *= KYBER_Q;
        i += c1;
    }
    i *= KYBER768_PACKED_POLY_PADDING;
    i += padding % KYBER768_PACKED_POLY_PADDING;

    let v = i.to_bytes_le();
    assert!(v.len() <= KYBER768_PACKED_POLY_SIZE);
    let mut r = [0; KYBER768_PACKED_SIZE];
    r[0..v.len()].clone_from_slice(v.as_ref());
    r[KYBER768_PACKED_POLY_SIZE..].clone_from_slice(&pk[(768 / 2 * 3)..]);
    r
}

fn unpack_kyber768(packed: &[u8; KYBER768_PACKED_SIZE]) -> [u8; 768 / 2 * 3 + 32] {
    let mut q = BigUint::from_bytes_le(&packed[..KYBER768_PACKED_POLY_SIZE]);

    let mut pk = [0; 768 / 2 * 3 + 32];
    q /= KYBER768_PACKED_POLY_PADDING;
    for i in (0..(768 / 2)).rev() {
        let c1 = (&q % KYBER_Q).to_u16().unwrap();
        q /= KYBER_Q;
        let c0 = (&q % KYBER_Q).to_u16().unwrap();
        q /= KYBER_Q;

        pk[i * 3 + 0] = (c0 & 0xff) as u8;
        pk[i * 3 + 1] = ((c0 >> 8) as u8) | (((c1 & 0x0f) as u8) << 4);
        pk[i * 3 + 2] = (c1 >> 4) as u8;
    }

    pk[(768 / 2 * 3)..].clone_from_slice(&packed[KYBER768_PACKED_POLY_SIZE..]);
    pk
}

pub struct PkLattice(kyber768::PublicKey);

pub struct SkLattice(kyber768::SecretKey);

pub type PkLatticeCl = <typenum::U1024 as Add<typenum::U132>>::Output;

pub type PkLatticeCompressed = GenericArray<u8, PkLatticeCl>;

pub type CipherText = GenericArray<u8, <typenum::U1024 as Add<typenum::U64>>::Output>;

pub type SharedSecret = GenericArray<u8, typenum::U32>;

pub struct Encapsulated {
    pub ss: SharedSecret,
    pub ct: CipherText,
}

impl PkLattice {
    pub fn compress<R>(&self, rng: &mut R) -> PkLatticeCompressed
    where
        R: rand::Rng,
    {
        let padding = loop {
            let p = rng.gen();
            if p & 0b111111 < KYBER768_PACKED_POLY_PADDING {
                break p;
            }
        };
        GenericArray::from_slice(pack_kyber768(self.0.as_bytes(), padding).as_ref()).clone()
    }

    pub fn decompress(c: &PkLatticeCompressed) -> Self {
        let data = unpack_kyber768(TryFrom::try_from(c.as_slice()).unwrap());
        PkLattice(kyber768::PublicKey::from_bytes(data.as_ref()).unwrap())
    }

    pub fn key_pair() -> (SkLattice, Self) {
        let (pk, sk) = kyber768::keypair();
        (SkLattice(sk), PkLattice(pk))
    }

    pub fn encapsulate(&self) -> Encapsulated {
        let (ss, ct) = kyber768::encapsulate(&self.0);
        Encapsulated {
            ss: GenericArray::from_slice(ss.as_bytes()).clone(),
            ct: GenericArray::from_slice(ct.as_bytes()).clone(),
        }
    }

    pub fn decapsulate(sk: &SkLattice, ct: &CipherText) -> SharedSecret {
        let ct = kyber768::Ciphertext::from_bytes(ct.as_ref()).unwrap();
        let ss = kyber768::decapsulate(&ct, &sk.0);
        GenericArray::from_slice(ss.as_bytes()).clone()
    }
}

impl AsRef<[u8]> for PkLattice {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}
