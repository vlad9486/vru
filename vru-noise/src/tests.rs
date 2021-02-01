use generic_array::GenericArray;
use rac::{Curve, LineValid};
use serde::{Serialize, Deserialize};
use core::{marker::PhantomData, ops::Mul};
use std::prelude::v1::Vec;
use super::SymmetricState;

#[test]
fn all() {
    let c: Cacophony = serde_json::from_str(include_str!("cacophony.json")).unwrap();
    c.vectors
        .iter()
        .find(|v| v.name == "Noise_XK_25519_AESGCM_SHA512")
        .map(Noise_XK_25519_AESGCM_SHA512)
        .unwrap()
}

#[derive(Serialize, Deserialize)]
pub struct Cacophony<'a> {
    #[serde(borrow)]
    vectors: Vec<TestVector<'a>>,
}

#[derive(Serialize, Deserialize)]
pub struct TestVector<'a> {
    #[serde(rename = "protocol_name")]
    name: &'a str,
    #[serde(rename = "init_prologue")]
    prologue: &'a [u8],

    #[serde(rename = "init_psks", default)]
    psks: Vec<&'a str>,

    init_remote_static: Option<&'a str>,
    init_static: Option<&'a str>,
    init_ephemeral: &'a str,
    resp_remote_static: Option<&'a str>,
    resp_static: Option<&'a str>,
    resp_ephemeral: Option<&'a str>,

    handshake_hash: &'a str,

    #[serde(borrow)]
    messages: [Pair<'a>; 6],
}

#[derive(Serialize, Deserialize)]
pub struct Pair<'a> {
    payload: &'a str,
    ciphertext: &'a str,
}

pub struct Point<C>
where
    C: Curve,
{
    secret: C::Scalar,
    public: C,
    compressed: GenericArray<u8, C::CompressedLength>,
}

impl<C> Point<C>
where
    C: Curve,
{
    fn new<'a>(hex: &'a str) -> Self {
        let mut secret = GenericArray::default();
        secret
            .as_mut_slice()
            .clone_from_slice(hex::decode(hex).unwrap().as_slice());
        let secret = <C::Scalar as LineValid>::try_clone_array(&secret).unwrap();
        let public = C::base().exp_ec(&secret);
        let compressed = public.compress();
        Point {
            secret: secret,
            public: public,
            compressed: compressed,
        }
    }
}

impl<'a, 'b, C> Mul<&'b Point<C>> for &'a Point<C>
where
    C: Curve,
{
    type Output = GenericArray<u8, C::CompressedLength>;

    fn mul(self, rhs: &'b Point<C>) -> Self::Output {
        self.public.exp_ec(&rhs.secret).compress()
    }
}

// AESGCM_SHA512
type C = (sha2::Sha512, byteorder::BigEndian, aes_gcm::Aes256Gcm);
// 25519
type P = Point<curve25519_dalek::montgomery::MontgomeryPoint>;

#[allow(non_snake_case)]
fn Noise_XK_25519_AESGCM_SHA512<'a>(v: &TestVector<'a>) {
    let init_ephemeral = P::new(v.init_ephemeral);
    let resp_ephemeral = P::new(v.resp_ephemeral.unwrap());
    let init_static = P::new(v.init_static.unwrap());
    let resp_static = P::new(v.resp_static.unwrap());

    let mut payload0 = hex::decode(v.messages[0].payload).unwrap();
    let mut payload1 = hex::decode(v.messages[1].payload).unwrap();
    let mut init_static_compressed = init_static.compressed.as_slice().to_vec();
    let mut payload2 = hex::decode(v.messages[2].payload).unwrap();

    let (cipher, _) = SymmetricState::new(v.name)
        .mix_hash(&hex::decode(v.prologue).unwrap())
        // <- s
        .mix_hash(&resp_static.compressed.as_ref())
        // -> e, es
        .mix_hash(&init_ephemeral.compressed.as_ref())
        .mix_shared_secret(&(&init_ephemeral * &resp_static))
        .encrypt(payload0.as_mut())
        .destruct(|tag| payload0.extend_from_slice(tag.as_ref()))
        // <- e, ee
        .mix_hash(resp_ephemeral.compressed.as_ref())
        .mix_shared_secret(&(&init_ephemeral * &resp_ephemeral))
        .encrypt(payload1.as_mut())
        .destruct(|tag| payload1.extend_from_slice(tag.as_ref()))
        // -> s, se
        .encrypt(init_static_compressed.as_mut())
        .destruct(|tag| init_static_compressed.extend_from_slice(tag.as_ref()))
        .mix_shared_secret(&(&init_static * &resp_ephemeral))
        .encrypt(payload2.as_mut())
        .destruct(|tag| payload2.extend_from_slice(tag.as_ref()))
        .finish::<PhantomData<C>>();

    let mut ct = Vec::new();
    ct.extend_from_slice(init_ephemeral.compressed.as_ref());
    ct.extend_from_slice(payload0.as_ref());
    let ct = hex::encode(ct);
    assert_eq!(v.messages[0].ciphertext, ct);

    let mut ct = Vec::new();
    ct.extend_from_slice(resp_ephemeral.compressed.as_ref());
    ct.extend_from_slice(payload1.as_ref());
    let ct = hex::encode(ct);
    assert_eq!(v.messages[1].ciphertext, ct);

    let mut ct = Vec::new();
    ct.extend_from_slice(init_static_compressed.as_ref());
    ct.extend_from_slice(payload2.as_ref());
    let ct = hex::encode(ct);
    assert_eq!(v.messages[2].ciphertext, ct);

    let _ = v.messages[3..]
        .iter()
        .fold(cipher.swap(), |mut cipher, pair| {
            let mut buffer = hex::decode(pair.payload).unwrap();
            let tag = cipher.encrypt(&[], buffer.as_mut());
            buffer.extend_from_slice(tag.as_ref());
            assert_eq!(pair.ciphertext, hex::encode(buffer));
            cipher.swap()
        });
}
