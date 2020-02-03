use crate::handshakes;
use super::TestVector;

use aes_gcm::Aes256Gcm;
use sha2::Sha256;
use curve25519_dalek::montgomery::MontgomeryPoint;
use generic_array::{
    GenericArray,
    typenum::{U15, U16, B0},
};

type A = (Aes256Gcm, Sha256, MontgomeryPoint, B0);
type P0 = GenericArray<u8, U16>;
type P1 = GenericArray<u8, U15>;

#[test]
#[allow(non_snake_case)]
fn Noise_IK_25519_AESGCM_SHA256() {
    let vector = TestVector {
        name: "Noise_IK_25519_AESGCM_SHA256",
        prologue: b"John Galt",
        local_static_hex: "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1",
        local_ephemeral_hex: "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a",
        remote_static_hex: "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893",
        remote_ephemeral_hex: "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b",
        psk_hex: None,
        hash_hex: "669c8640d9e42a3cda2f232f78597ceefb01daa6e3df81181ccce6fc6b5026bf",
        messages: [
            (
                "\
                 4c756477696720766f6e204d69736573",
                "\
                 ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944\
                 4e417bc55c7a8166c993356c1be41ef67818a292426f301556c7f26b21d25ddb\
                 097153891a9a956cff47b83e63ad8d70\
                 1c1342c209cff1ca5ecd43402762ac24\
                 9e3bd3a4c0a145fe07cb5dae28ea13a3",
            ),
            (
                "\
                 4d757272617920526f746862617264",
                "\
                 95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843\
                 af2ccf9972e22afc67aeafcd25162f\
                 7f98c363b7762e3e4cb7d272e39f27a5",
            ),
            (
                "462e20412e20486179656b",
                "66acfc92e3197de166809e6d4d5d003dcc819a84bc3522ca53c9d9",
            ),
            (
                "4361726c204d656e676572",
                "71f89aa6533a6de70b0826864dd75f60806ee40170c16290189eb3",
            ),
            (
                "4a65616e2d426170746973746520536179",
                "4795a3423550c8bf00386bd496a3e2c76c10669d2a75ab8f79b5094c5412a25705",
            ),
            (
                "457567656e2042f6686d20766f6e2042617765726b",
                "aa0bb39097555c918e40be82abc2b909eb79d9eb87adb07e268fc37323a6cf904fd01fb391",
            ),
        ],
    };

    vector.test::<A, handshakes::IK<A, P0, P1>>();
}

#[test]
#[allow(non_snake_case)]
fn Noise_IKpsk1_25519_AESGCM_SHA256() {
    let vector = TestVector {
        name: "Noise_IKpsk1_25519_AESGCM_SHA256",
        prologue: b"John Galt",
        local_static_hex: "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1",
        local_ephemeral_hex: "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a",
        remote_static_hex: "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893",
        remote_ephemeral_hex: "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b",
        psk_hex: Some("54686973206973206d7920417573747269616e20706572737065637469766521"),
        hash_hex: "60b2cc6a78e5c5170469bf6be88f6f083363113fe4216b791f04c79659884185",
        messages: [
            (
                "\
                 4c756477696720766f6e204d69736573",
                "\
                 ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944\
                 cf5aec5a69cc937598c005d3f36940abe166f1eab777e15d8958d533d2d5eca2\
                 967c66cfc0788d6197989cac53ecb8e9\
                 cb04a2ff8bdf3a9d2bf1897b492c8463\
                 9583c5486e0205e4012ac81400e569cb",
            ),
            (
                "\
                 4d757272617920526f746862617264",
                "\
                 95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843\
                 746e1ca9059ed09501f41b1c01dd32\
                 378315c2d754bdc29ced08b435f05259",
            ),
            (
                "462e20412e20486179656b",
                "232fe1ce5018b3cd1e732e72894d61fc242473f6919344e30e569a",
            ),
            (
                "4361726c204d656e676572",
                "419f5c6e5b039e67e125bcd7fb1cfbb79720ef97e8a3cb2c5a660a",
            ),
            (
                "4a65616e2d426170746973746520536179",
                "086a04808638c811bb91733c7c6df2a475df82dba1ed7af5251cf4e6e13ccf4376",
            ),
            (
                "457567656e2042f6686d20766f6e2042617765726b",
                "654b5ee2e3d367a1c1dfc242f53471f3e74e108562e66b0ed5d71327f02d08b17b5eb5fa6d",
            ),
        ],
    };
    vector.test::<A, handshakes::IKpsk1<A, P0, P1>>();
}
