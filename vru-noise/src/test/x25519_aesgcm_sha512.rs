use crate::handshakes;
use super::TestVector;

use aes_gcm::Aes256Gcm;
use sha2::Sha512;
use curve25519_dalek::montgomery::MontgomeryPoint;
use generic_array::{
    GenericArray,
    typenum::{U15, U16, B0},
};

type A = (Aes256Gcm, Sha512, MontgomeryPoint, B0);
type P0 = GenericArray<u8, U16>;
type P1 = GenericArray<u8, U15>;

#[test]
#[allow(non_snake_case)]
fn Noise_IK_25519_AESGCM_SHA512() {
    let vector = TestVector {
        name: "Noise_IK_25519_AESGCM_SHA512",
        prologue: b"John Galt",
        local_static_hex: "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1",
        local_ephemeral_hex: "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a",
        remote_static_hex: "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893",
        remote_ephemeral_hex: "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b",
        psk_hex: None,
        hash_hex: "\
                   6eb7af04466fb3a1561f53ee65dc261ff26e01417fc1a2066ac0e8d4060775d6\
                   a76d002f3d769446ebba4d7fa2347e6692515f9b6bc8601067c53ae4b9615af0",
        messages: [
            (
                "\
                 4c756477696720766f6e204d69736573",
                "\
                 ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944\
                 1edc6a898ac79b09a5e21a391d717cc9fe6207726ca03a1ec47e7efa6ae61cba\
                 2c392f2f30d00850077641ed02d38c0f\
                 11bed6a3a668b33ecd3f324773f79192\
                 1f8ee5b0d422bd6831686aef505dcd88",
            ),
            (
                "\
                 4d757272617920526f746862617264",
                "\
                 95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843\
                 c9993ca1fc214af8c6a4e228b2b5d6\
                 6106b2bbc5e4537cc17655e44ace079a",
            ),
            (
                "462e20412e20486179656b",
                "c9f752880da6468eb9bf272293d8d3d1bf88130372e4d26f12b921",
            ),
            (
                "4361726c204d656e676572",
                "9bec50cd609e30cbc702417247b3854fbed537decc2b2366bf343a",
            ),
            (
                "4a65616e2d426170746973746520536179",
                "c27c79d9d975652bdf091c566ccdf385d2f6f8ddffecfcafd80d9dad70b7f6ca5f",
            ),
            (
                "457567656e2042f6686d20766f6e2042617765726b",
                "12f01efb31171bdfd3263e601784d51d51872897e169ac8a382388de223103f3f6c211186b",
            ),
        ],
    };

    vector.test::<A, handshakes::IK<A, P0, P1>>();
}
