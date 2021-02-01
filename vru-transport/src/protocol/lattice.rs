use std::{
    ops::{Add, Mul},
    fmt,
};
use rac::{Array, LineValid, Line, Concat, generic_array::typenum};
use sha3::{
    Sha3_256,
    digest::{Update, FixedOutput},
};
use vru_kyber::{Kyber, Kem};

// 32 * 11 * 3 + 32 = 32 * 34
type PkLatticeL = <typenum::U32 as Mul<typenum::U34>>::Output;

pub struct PkLattice(Concat<Array<PkLatticeL>, Array<typenum::U32>>);

impl fmt::Debug for PkLattice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PublicKey")
            .field(&hex::encode(self.0 .0))
            .finish()
    }
}

impl Clone for PkLattice {
    fn clone(&self) -> Self {
        match self {
            &PkLattice(Concat(ref l, ref h)) => PkLattice(Concat(l.clone(), h.clone())),
        }
    }
}

#[derive(Clone)]
pub struct SkLattice(Array<<typenum::U1024 as Add<typenum::U256>>::Output>);

pub type PkLatticeCl = PkLatticeL;

pub type PkLatticeCompressed = Array<PkLatticeCl>;

// 32 * 11 * 3 + 32 * 3 = 32 * 36
pub type CipherText = Array<<typenum::U32 as Mul<typenum::U36>>::Output>;

pub type SharedSecret = Array<typenum::U32>;

pub struct Encapsulated {
    pub ss: SharedSecret,
    pub ct: CipherText,
}

impl PkLattice {
    pub fn compress(&self) -> PkLatticeCompressed {
        self.0 .0.clone()
    }

    pub fn decompress(c: &PkLatticeCompressed) -> Self {
        let hash = Sha3_256::default().chain(&c).finalize_fixed();
        PkLattice(Concat(c.clone(), hash))
    }

    pub fn hash(&self) -> Array<typenum::U32> {
        self.0 .1.clone()
    }

    pub fn key_pair(seed: &Array<typenum::U64>) -> (SkLattice, Self) {
        let (pk, sk) = <Kyber<typenum::U3> as Kem>::generate_pair(seed);
        let pk_bytes = pk.clone_line();
        let hash = Sha3_256::default().chain(&pk_bytes).finalize_fixed();

        (
            SkLattice(sk.0.clone_line()),
            PkLattice(Concat(pk_bytes, hash)),
        )
    }

    pub fn encapsulate(&self, seed: &Array<typenum::U32>) -> Encapsulated {
        let pk = Line::clone_array(&self.0 .0);
        let (ct, ss) = <Kyber<typenum::U3> as Kem>::encapsulate(&seed, &pk, &self.0 .1);
        Encapsulated {
            ss: ss,
            ct: ct.clone_line(),
        }
    }

    pub fn decapsulate(&self, sk: &SkLattice, ct: &CipherText) -> SharedSecret {
        let pk = Line::clone_array(&self.0 .0);
        let sk = Concat(Line::clone_array(&sk.0), pk);
        <Kyber<typenum::U3> as Kem>::decapsulate(&sk, &self.0 .1, &Line::clone_array(&ct))
    }
}
