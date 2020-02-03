use crate::handshakes;
use super::TestVector;

use chacha20poly1305::ChaCha20Poly1305;
use sha2::Sha256;
use curve25519_dalek::montgomery::MontgomeryPoint;
use generic_array::{
    GenericArray,
    typenum::{U15, U16, B0},
};

type A = (ChaCha20Poly1305, Sha256, MontgomeryPoint, B0);
type P0 = GenericArray<u8, U16>;
type P1 = GenericArray<u8, U15>;

#[test]
#[allow(non_snake_case)]
fn Noise_IK_25519_ChaChaPoly_SHA256() {
    let vector = TestVector {
        name: "Noise_IK_25519_ChaChaPoly_SHA256",
        prologue: b"John Galt",
        local_static_hex: "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1",
        local_ephemeral_hex: "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a",
        remote_static_hex: "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893",
        remote_ephemeral_hex: "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b",
        psk_hex: None,
        hash_hex: "0b0f68fb0c27e03ce9b97565995ed4838cc0581b762ef72b062f6a546419fad7",
        messages: [
            (
                "\
                 4c756477696720766f6e204d69736573",
                "\
                 ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944\
                 718da798efbcd91528520204f904b9bd6c7413dccdc214d951e15253e39987f1\
                 8146e8cd0873654207148333479d4d16\
                 c289f0294b29960a72f48e0b7bba2e89\
                 083169825e59642148d492020664ccf7",
            ),
            (
                "\
                 4d757272617920526f746862617264",
                "\
                 95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843\
                 5361e70b2ed446e6c9ec387d1d6b3b\
                 840f194e373979d241b203c4acafccf5",
            ),
            (
                "462e20412e20486179656b",
                "050e9f3c8fac16b68dbce8f8c4bfbf6617c897f9ada4aa29aa19c8",
            ),
            (
                "4361726c204d656e676572",
                "344233a6cabb7141d80f3da2fedc311d9646bbb0f505afe403a667",
            ),
            (
                "4a65616e2d426170746973746520536179",
                "62cdeeb172ad7ade7aa7d9e069da5790f12331bfa00177787a1d0810c67dc3b2b4",
            ),
            (
                "457567656e2042f6686d20766f6e2042617765726b",
                "029bead1b40992327044d409d9a1f3ad8f36c3c452775d557e18bbeb2e8dfcead32d514024",
            ),
        ],
    };
    vector.test::<A, handshakes::IK<A, P0, P1>>();
}

#[test]
#[allow(non_snake_case)]
fn Noise_IKpsk1_25519_ChaChaPoly_SHA256() {
    let vector = TestVector {
        name: "Noise_IKpsk1_25519_ChaChaPoly_SHA256",
        prologue: b"John Galt",
        local_static_hex: "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1",
        local_ephemeral_hex: "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a",
        remote_static_hex: "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893",
        remote_ephemeral_hex: "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b",
        psk_hex: Some("54686973206973206d7920417573747269616e20706572737065637469766521"),
        hash_hex: "3ad252ed6f724c52da3450383b7d8b806c183e1ef157bbe0465ad24997ec4717",
        messages: [
            (
                "\
                 4c756477696720766f6e204d69736573",
                "\
                 ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944\
                 ac58a6c31948ce200911c5b27b67f1c4d1bed490532dd94ed17164fcc5784d37\
                 30fc302b70cc0f19beedaeb56bd974c0\
                 e57d747d11534c746eb2a32ac3fde3e4\
                 cdf6c3a4705762a6c6ca664b3bc89490",
            ),
            (
                "\
                 4d757272617920526f746862617264",
                "\
                 95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843\
                 846a944a0652fb390d213d0700d5ae\
                 8fef7aad0ecc79a9216d15de5d7f3ee4",
            ),
            (
                "462e20412e20486179656b",
                "5d872673f64813a47a00369b15c8da92691605ad71ba019de8e718",
            ),
            (
                "4361726c204d656e676572",
                "2045266a750b6af2547f7eb1391058196b742d0aac4b3a1bcc1913",
            ),
            (
                "4a65616e2d426170746973746520536179",
                "9ec47ed0e7628c7d7a4eed631b963740ac2fd754eadaa9232e99054af4f7b29174",
            ),
            (
                "457567656e2042f6686d20766f6e2042617765726b",
                "310e359407350594cfb96eb4596e35677d4a71ceb42aa8cbba097bb9e7150b0d1bd749c4aa",
            ),
        ],
    };
    vector.test::<A, handshakes::IKpsk1<A, P0, P1>>();
}
