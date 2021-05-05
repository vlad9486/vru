use std::{fmt, str::FromStr};
use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
use rac::{Array, LineValid, Concat, Curve, generic_array::typenum};
use serde::{Serialize, Deserialize};
use super::lattice::{PkLattice, SkLattice, PkLatticeCompressed};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKey {
    pub(super) elliptic: EdwardsPoint,
    pub(super) lattice: PkLattice,
}

#[derive(Clone)]
pub struct SecretKey {
    pub(super) elliptic: Scalar,
    pub(super) lattice: SkLattice,
}

impl PublicKey {
    pub fn key_pair<R>(rng: &mut R) -> (SecretKey, Self)
    where
        R: rand::Rng,
    {
        let mut seed = Array::default();
        rng.fill_bytes(seed.as_mut());
        Self::key_pair_seed(&seed)
    }

    pub fn key_pair_seed(seed: &Array<typenum::U96>) -> (SecretKey, Self) {
        let e_sk = Scalar::try_clone_array(&Array::from_slice(&seed[..32])).unwrap();
        let e_pk = EdwardsPoint::base().exp_ec(&e_sk);
        let (pq_sk, pq_pk) = PkLattice::key_pair(Array::from_slice(&seed[32..]));

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

pub type PublicKeyCompressed =
    Concat<Array<<EdwardsPoint as Curve>::CompressedLength>, PkLatticeCompressed>;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct PublicIdentity {
    pub(super) elliptic: Array<<EdwardsPoint as Curve>::CompressedLength>,
    pub(super) lattice: Array<typenum::U32>,
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
        bytes[2..34].clone_from_slice(&self.elliptic);
        bytes[34..].clone_from_slice(&self.lattice);
        write!(f, "{}", base64::encode(bytes))
    }
}

impl FromStr for PublicIdentity {
    type Err = base64::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = base64::decode(s)?;
        let mut elliptic_array = Array::default();
        elliptic_array
            .as_mut_slice()
            .clone_from_slice(&bytes[2..34]);
        let mut lattice_array = Array::default();
        lattice_array.as_mut_slice().clone_from_slice(&bytes[34..]);
        Ok(PublicIdentity {
            elliptic: elliptic_array,
            lattice: lattice_array,
        })
    }
}
