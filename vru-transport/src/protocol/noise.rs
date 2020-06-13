use vru_noise::{CipherPair, Pattern, SimpleRotor};
use secp256k1::PublicKey;
use sha2::Sha256;
use chacha20poly1305::ChaCha20Poly1305;

pub type CipherAlgorithm = (ChaCha20Poly1305, Sha256);
pub type Noise = (CipherAlgorithm, PublicKey);
pub type Cipher = CipherPair<CipherAlgorithm, SimpleRotor<CipherAlgorithm>>;

pub type XkZero = Pattern![Noise, "<- s"];
pub type XkOne<P> = Pattern! [ Noise, "-> e, es" P ];
pub type XkTwo<P> = Pattern! [ Noise, "<- e, ee" P ];
pub type XkThree<P> = Pattern! [ Noise, "-> S, se" P ];

pub type IkZero = Pattern![Noise, "<- s"];
pub type IkOne<P> = Pattern! [ Noise, "-> e, es, S, ss" P ];
pub type IkTwo<P> = Pattern! [ Noise, "<- e, ee, se" P ];
