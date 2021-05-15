use core::marker::PhantomData;
use pq_kem::Kem;
use rac::{
    LineValid, Line, Concat,
    generic_array::{GenericArray, ArrayLength, typenum},
};
use subtle::{ConstantTimeEq, ConditionallySelectable};
use sha3::{
    Sha3_256, Sha3_512,
    digest::{Update, FixedOutput},
};
use super::{
    coefficient::Coefficient,
    poly_inner::{PolyInner, Cbd},
    poly::{Poly, Ntt},
    indcpa::{C, SecretKey, PublicKey, CipherText, key_pair, encapsulate, decapsulate},
};

pub type S = typenum::U32;

pub type SkReject<W> = Concat<SecretKey<S, W>, GenericArray<u8, typenum::U32>>;

pub struct Kyber<W>(PhantomData<W>);

impl<W> Kem for Kyber<W>
where
    W: ArrayLength<GenericArray<Poly<S, typenum::B0>, W>>,
    W: ArrayLength<Poly<S, typenum::B0>>,
    W: ArrayLength<Poly<S, typenum::B1>>,
    W: ArrayLength<Coefficient>,
    PolyInner<S>: Cbd<S, W>,
    Poly<S, typenum::B1>: Ntt<Output = Poly<S, typenum::B0>>,
    Poly<S, typenum::B0>: Ntt<Output = Poly<S, typenum::B1>>,
    SecretKey<S, W>: LineValid,
    PublicKey<S, W>: LineValid,
    CipherText<S, W>: LineValid,
    SkReject<W>: LineValid,
{
    type PublicKey = PublicKey<S, W>;
    type SecretKey = SkReject<W>;
    type CipherText = CipherText<S, W>;
    type PairSeedLength = typenum::U64;
    type PublicKeyHashLength = typenum::U32;
    type EncapsulationSeedLength = typenum::U32;
    type SharedSecretLength = typenum::U32;

    fn generate_pair(
        seed: &GenericArray<u8, Self::PairSeedLength>,
    ) -> (Self::PublicKey, Self::SecretKey) {
        let Concat(seed, reject) = C::clone_array(seed);
        let (sk, pk) = key_pair(&seed);
        (pk, Concat(sk, reject))
    }

    fn encapsulate(
        seed: &GenericArray<u8, Self::EncapsulationSeedLength>,
        public_key: &Self::PublicKey,
        public_key_hash: &GenericArray<u8, Self::PublicKeyHashLength>,
    ) -> (Self::CipherText, GenericArray<u8, Self::SharedSecretLength>) {
        let message = Sha3_256::default().chain(seed).finalize_fixed();
        let c = Sha3_512::default()
            .chain(&message)
            .chain(&public_key_hash)
            .finalize_fixed();
        let Concat(r, noise_seed) = C::clone_array(&c);

        let ct = encapsulate(&noise_seed, &message, public_key);

        let ct_hash = Sha3_256::default().chain(ct.clone_line()).finalize_fixed();
        let ss = Sha3_256::default()
            .chain(Concat(r, ct_hash).clone_line())
            .finalize_fixed();
        (ct, ss)
    }

    fn decapsulate(
        secret_key: &Self::SecretKey,
        public_key: &Self::PublicKey,
        public_key_hash: &GenericArray<u8, Self::PublicKeyHashLength>,
        cipher_text: &Self::CipherText,
    ) -> GenericArray<u8, Self::SharedSecretLength> {
        let Concat(ref sk, reject) = secret_key;
        let pk_bytes = public_key.clone_line();
        let pk = PublicKey::try_clone_array(&pk_bytes).unwrap();

        let message = decapsulate(cipher_text, sk);
        let c = Sha3_512::default()
            .chain(&message)
            .chain(&public_key_hash)
            .finalize_fixed();
        let Concat(mut r, noise_seed) = C::clone_array(&c);

        let ct = encapsulate(&noise_seed, &message, &pk).clone_line();
        let ct_prime = cipher_text.clone_line();
        let flag = ct.ct_eq(ct_prime.as_ref());

        let ct_hash = Sha3_256::default().chain(ct).finalize_fixed();
        for i in 0..32 {
            r[i].conditional_assign(&reject[i], !flag);
        }

        Sha3_256::default()
            .chain(Concat(r, ct_hash).clone_line())
            .finalize_fixed()
    }
}

#[cfg(test)]
mod tests {
    use std::{prelude::v1::Vec, marker::PhantomData};
    use rac::{
        LineValid, Concat,
        generic_array::{
            GenericArray,
            typenum::{self, Unsigned},
        },
    };
    use sha3::{
        Sha3_256,
        digest::{Update, FixedOutput},
    };
    use serde::Deserialize;
    use super::{Kem, Kyber};

    #[derive(Deserialize)]
    struct TestVector<'a, W> {
        width: i64,
        pair_seed: &'a str,
        reject_secret: &'a str,
        secret_key: &'a str,
        public_key: &'a str,
        encapsulation_seed: &'a str,
        cipher_text: &'a str,
        shared_secret: &'a str,
        #[serde(default)]
        phantom_data: PhantomData<W>,
    }

    impl<'a, W> TestVector<'a, W>
    where
        W: Unsigned,
        Kyber<W>: Kem,
        Concat<<Kyber<W> as Kem>::SecretKey, <Kyber<W> as Kem>::PublicKey>: LineValid,
    {
        fn from_json() -> Self {
            let json_text = include_str!("test_vectors.json");
            // it is a lie, `TestVector` instances has different `W` parameter
            let value = serde_json::from_str::<Vec<TestVector<W>>>(json_text).unwrap();
            value
                .into_iter()
                .find(|t| t.width == (W::USIZE as i64))
                .unwrap()
        }

        fn seed(&self) -> GenericArray<u8, <Kyber<W> as Kem>::PairSeedLength> {
            let pair_seed = hex::decode(self.pair_seed).unwrap();
            let reject_secret = hex::decode(self.reject_secret).unwrap();
            let mut s = GenericArray::default();
            s[..32].clone_from_slice(pair_seed.as_ref());
            s[32..].clone_from_slice(reject_secret.as_ref());
            s
        }

        fn secret_key_bytes(
            &self,
        ) -> GenericArray<u8, <Concat<<Kyber<W> as Kem>::SecretKey, <Kyber<W> as Kem>::PublicKey> as LineValid>::Length>{
            GenericArray::from_slice(hex::decode(self.secret_key).unwrap().as_ref()).clone()
        }

        fn public_key_bytes(
            &self,
        ) -> GenericArray<u8, <<Kyber<W> as Kem>::PublicKey as LineValid>::Length> {
            GenericArray::from_slice(hex::decode(self.public_key).unwrap().as_ref()).clone()
        }

        fn encapsulation_seed(
            &self,
        ) -> GenericArray<u8, <Kyber<W> as Kem>::EncapsulationSeedLength> {
            GenericArray::from_slice(hex::decode(self.encapsulation_seed).unwrap().as_ref()).clone()
        }

        fn cipher_text_bytes(
            &self,
        ) -> GenericArray<u8, <<Kyber<W> as Kem>::CipherText as LineValid>::Length> {
            GenericArray::from_slice(hex::decode(self.cipher_text).unwrap().as_ref()).clone()
        }

        fn shared_secret(&self) -> GenericArray<u8, <Kyber<W> as Kem>::SharedSecretLength> {
            GenericArray::from_slice(hex::decode(self.shared_secret).unwrap().as_ref()).clone()
        }
    }

    fn generic<W>()
    where
        W: Unsigned,
        Kyber<W>: Kem<PublicKeyHashLength = <Sha3_256 as FixedOutput>::OutputSize>,
        Concat<<Kyber<W> as Kem>::SecretKey, <Kyber<W> as Kem>::PublicKey>: LineValid,
    {
        let v = TestVector::from_json();

        let (pk, sk) = Kyber::<W>::generate_pair(&v.seed());
        let pk_bytes = pk.clone_line();
        let sk_full = Concat(sk, pk);
        assert_eq!(sk_full.clone_line(), v.secret_key_bytes());
        let Concat(sk, _) = sk_full;
        assert_eq!(pk_bytes, v.public_key_bytes());
        let pk = LineValid::try_clone_array(&pk_bytes).unwrap();
        let hash = Sha3_256::default().chain(pk_bytes).finalize_fixed();
        let (ct, ss_0) = Kyber::<W>::encapsulate(&v.encapsulation_seed(), &pk, &hash);
        let ct_bytes = ct.clone_line();
        assert_eq!(ct_bytes, v.cipher_text_bytes());
        let ct = LineValid::try_clone_array(&ct_bytes).unwrap();
        let ss_1 = Kyber::<W>::decapsulate(&sk, &pk, &hash, &ct);
        assert_eq!(ss_0, v.shared_secret());
        assert_eq!(ss_0, ss_1);
    }

    #[test]
    fn test_2() {
        generic::<typenum::U2>()
    }

    #[test]
    fn test_3() {
        generic::<typenum::U3>()
    }

    #[test]
    fn test_4() {
        generic::<typenum::U4>()
    }
}
