use std::{ops::Mul, fmt, str::FromStr};
use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
use serde::{Serialize, Deserialize};
use rac::{Array, Concat, Curve, LineValid, Line, generic_array::typenum};
use self::lattice::{Sk, Pk, PkHash};
pub use self::lattice::{Ct, SharedSecret, Encapsulated};

pub struct PublicKey {
    elliptic: EdwardsPoint,
    lattice: Pk,
    lattice_hash: PkHash,
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("elliptic", &self.elliptic)
            .field("lattice", &hex::encode(&self.lattice()))
            .finish()
    }
}

impl PublicKey {
    pub fn gen(seed: &Array<typenum::U96>) -> (Self, SecretKey) {
        let e_sk = Scalar::try_clone_array(Array::from_slice(&seed[..32])).unwrap();
        let e_pk = EdwardsPoint::base().exp_ec(&e_sk);
        let (l_pk, l_sk) = lattice::gen(Array::from_slice(&seed[32..]));
        let l_hash = lattice::pk_hash(&l_pk);
        (
            PublicKey {
                elliptic: e_pk,
                lattice: l_pk,
                lattice_hash: l_hash,
            },
            SecretKey {
                elliptic: e_sk,
                lattice: l_sk,
            },
        )
    }

    pub fn decompress(bytes: PublicKeyBytes) -> Self {
        let Concat(elliptic_bytes, lattice_bytes) = bytes;
        let lattice = Pk::clone_array(&lattice_bytes);
        let elliptic = EdwardsPoint::try_clone_array(&elliptic_bytes).unwrap();
        let lattice_hash = lattice::pk_hash(&lattice);
        PublicKey {
            elliptic,
            lattice,
            lattice_hash,
        }
    }

    pub fn elliptic(&self) -> Array<typenum::U32> {
        Curve::compress(&self.elliptic)
    }

    // 32 * 11 * 3 + 32 = 32 * 34
    pub fn lattice(&self) -> PublicKeyLatticeBytes {
        self.lattice.clone_line()
    }

    pub fn lattice_hash(&self) -> Array<typenum::U32> {
        self.lattice_hash
    }

    pub fn compress(&self) -> PublicKeyBytes {
        Concat(self.elliptic(), self.lattice())
    }

    pub fn dh(&self, other: &SecretKey) -> SharedSecret {
        self.elliptic.exp_ec(&other.elliptic).clone_line()
    }

    pub fn encapsulate(&self, seed: &Array<typenum::U32>) -> Encapsulated {
        lattice::encapsulate(&self.lattice, &self.lattice_hash, seed)
    }

    pub fn decapsulate(&self, sk: &SecretKey, ct: &Ct) -> SharedSecret {
        lattice::decapsulate(&self.lattice, &self.lattice_hash, &sk.lattice, ct)
    }

    pub fn identity(&self) -> Identity {
        use sha3::{
            Sha3_256,
            digest::{Digest, FixedOutput},
        };

        let bytes = self.compress().clone_line();
        let hash = Sha3_256::default().chain(&bytes).finalize_fixed();
        Identity { hash }
    }
}

pub type PublicKeyLatticeBytes = Array<<typenum::U32 as Mul<typenum::U34>>::Output>;
pub type PublicKeyBytes = Concat<Array<typenum::U32>, PublicKeyLatticeBytes>;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Identity {
    hash: Array<typenum::U32>,
}

impl AsRef<[u8]> for Identity {
    fn as_ref(&self) -> &[u8] {
        self.hash.as_ref()
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bytes = [0; 33];
        bytes[1..33].clone_from_slice(&self.hash);
        write!(f, "{}", base64::encode(bytes))
    }
}

impl FromStr for Identity {
    type Err = base64::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = base64::decode(s)?;
        let mut hash = Array::default();
        hash.as_mut_slice().clone_from_slice(&bytes[1..33]);
        Ok(Identity { hash })
    }
}

pub struct SecretKey {
    elliptic: Scalar,
    lattice: Sk,
}

mod implementations {
    use serde::{ser, de};
    use rac::{Concat, Line, LineLike, LineValid};
    use super::{PublicKey, SecretKey};

    impl ser::Serialize for PublicKey {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: ser::Serializer,
        {
            let a = self.elliptic.clone_line();
            let b = self.lattice.clone_line();
            let c = self.lattice_hash;
            LineLike(Concat(a, Concat(b, c))).serialize(serializer)
        }
    }

    impl<'de> de::Deserialize<'de> for PublicKey {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            let LineLike(Concat(a, Concat(b, c))) = de::Deserialize::deserialize(deserializer)?;
            Ok(PublicKey {
                elliptic: LineValid::try_clone_array(&a).unwrap(),
                lattice: Line::clone_array(&b),
                lattice_hash: c,
            })
        }
    }

    impl Clone for PublicKey {
        fn clone(&self) -> Self {
            PublicKey {
                elliptic: LineValid::try_clone_array(&self.elliptic.clone_line()).unwrap(),
                lattice: Line::clone_array(&self.lattice.clone_line()),
                lattice_hash: self.lattice_hash,
            }
        }
    }

    impl Clone for SecretKey {
        fn clone(&self) -> Self {
            let sk_bytes = self.lattice.clone_line();
            SecretKey {
                elliptic: self.elliptic,
                lattice: Line::clone_array(&sk_bytes),
            }
        }
    }
}

mod lattice {
    use sha3::{
        Sha3_256,
        digest::{Digest, FixedOutput},
    };
    use rac::{Array, LineValid, generic_array::typenum};
    use vru_kyber::{Kyber, Kem};

    pub type Pk = <Kyber<typenum::U3> as Kem>::PublicKey;
    pub type PkHash = Array<<Kyber<typenum::U3> as Kem>::PublicKeyHashLength>;

    pub type Sk = <Kyber<typenum::U3> as Kem>::SecretKey;

    pub type Ct = <Kyber<typenum::U3> as Kem>::CipherText;

    pub type SharedSecret = Array<typenum::U32>;

    pub struct Encapsulated {
        pub ss: SharedSecret,
        pub ct: Ct,
    }

    pub fn gen(seed: &Array<typenum::U64>) -> (Pk, Sk) {
        <Kyber<typenum::U3> as Kem>::generate_pair(seed)
    }

    pub fn pk_hash(pk: &Pk) -> PkHash {
        let pk_bytes = pk.clone_line();
        Sha3_256::default().chain(&pk_bytes).finalize_fixed()
    }

    pub fn encapsulate(pk: &Pk, pk_hash: &PkHash, seed: &Array<typenum::U32>) -> Encapsulated {
        let (ct, ss) = <Kyber<typenum::U3> as Kem>::encapsulate(&seed, &pk, &pk_hash);
        Encapsulated { ss, ct }
    }

    pub fn decapsulate(pk: &Pk, pk_hash: &PkHash, sk: &Sk, ct: &Ct) -> SharedSecret {
        <Kyber<typenum::U3> as Kem>::decapsulate(sk, pk, pk_hash, &ct)
    }
}
