use vru_sphinx::AuthenticatedMessage;
use secp256k1::SecretKey;
use sha2::Sha256;
use chacha20::ChaCha20;
use hmac::Hmac;
use generic_array::{
    GenericArray,
    typenum::{U4, U19, U181, U233},
};

pub type Sphinx = (SecretKey, Hmac<Sha256>, Sha256, ChaCha20);

/// size = 33 + (19 + 32) * 4 + 32 + 115 = 384 <= 0x1fc
pub type OutgoingInitialPacket = AuthenticatedMessage<Sphinx, U19, U4, GenericArray<u8, U181>>;
/// size = 33 + (19 + 32) * 4 + 32 + 105 + 32 * 4 = 502 <= 0x1fc
pub type IncomingInitialPacket = AuthenticatedMessage<Sphinx, U19, U4, GenericArray<u8, U233>>;
