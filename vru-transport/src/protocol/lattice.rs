use std::{ops::Add, fmt};
use rac::{
    LineValid, Line, Concat,
    generic_array::{GenericArray, sequence::GenericSequence, typenum},
};
use sha3::{
    Sha3_256,
    digest::{Update, FixedOutput},
};
use vru_kyber::{Kyber, Kem};

type PkLatticeL = <typenum::U1024 as Add<typenum::U64>>::Output;

pub struct PkLattice(Concat<GenericArray<u8, PkLatticeL>, GenericArray<u8, typenum::U32>>);

impl fmt::Debug for PkLattice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PublicKey")
            .field(&hex::encode(self.clone_line()))
            .finish()
    }
}

impl LineValid for PkLattice {
    type Length = <typenum::U1024 as Add<typenum::U96>>::Output;

    fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
        Concat::try_clone_array(a).map(PkLattice)
    }

    fn clone_line(&self) -> GenericArray<u8, Self::Length> {
        self.0.clone_line()
    }
}

impl Line for PkLattice {
    fn clone_array(a: &GenericArray<u8, Self::Length>) -> Self {
        Self::try_clone_array(a).unwrap()
    }
}

impl Clone for PkLattice {
    fn clone(&self) -> Self {
        Self::clone_array(&self.clone_line())
    }
}

#[derive(Clone)]
pub struct SkLattice(GenericArray<u8, <typenum::U1024 as Add<typenum::U256>>::Output>);

pub type PkLatticeCl = <typenum::U1024 as Add<typenum::U64>>::Output;

pub type PkLatticeCompressed = GenericArray<u8, PkLatticeCl>;

pub type CipherText = GenericArray<u8, <typenum::U1024 as Add<typenum::U128>>::Output>;

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
        let _ = rng;
        self.0 .0.clone()
    }

    pub fn decompress(c: &PkLatticeCompressed) -> Self {
        let hash = Sha3_256::default().chain(&c).finalize_fixed();
        PkLattice(Concat(c.clone(), hash))
    }

    pub fn hash(&self) -> GenericArray<u8, typenum::U32> {
        self.0 .1.clone()
    }

    pub fn key_pair(seed: &GenericArray<u8, typenum::U64>) -> (SkLattice, Self) {
        let (pk, sk) = <Kyber<typenum::U3> as Kem>::generate_pair(seed);
        let pk_bytes = pk.clone_line();
        let hash = Sha3_256::default().chain(&pk_bytes).finalize_fixed();

        (
            SkLattice(sk.0.clone_line()),
            PkLattice(Concat(pk_bytes, hash)),
        )
    }

    pub fn encapsulate<R>(&self, rng: &mut R) -> Encapsulated
    where
        R: rand::Rng,
    {
        let seed = GenericArray::generate(|_| rng.gen());
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
