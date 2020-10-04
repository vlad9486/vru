use vru_sphinx::AuthenticatedMessage;
use curve25519_dalek::edwards::EdwardsPoint;
use sha2::Sha256;
use chacha20::ChaCha20;
use hmac::Hmac;
use generic_array::{GenericArray, typenum};

pub type Sphinx = (EdwardsPoint, Hmac<Sha256>, Sha256, ChaCha20);

/// size = 33 + (19 + 32) * 4 + 32 + 115 = 384 <= 0x1fc
pub type OutgoingInitialPacket =
    AuthenticatedMessage<Sphinx, typenum::U19, typenum::U4, GenericArray<u8, typenum::U181>>;
/// size = 33 + (19 + 32) * 4 + 32 + 105 + 32 * 4 = 502 <= 0x1fc
pub type IncomingInitialPacket =
    AuthenticatedMessage<Sphinx, typenum::U19, typenum::U4, GenericArray<u8, typenum::U233>>;
