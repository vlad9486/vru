use vru_sphinx::{PseudoRandomStream, AuthenticatedMessage};
use secp256k1::SecretKey;
use sha2::Sha256;
use chacha::{ChaCha, Error as ChaChaError, SeekableKeyStream, KeyStream};
use hmac::Hmac;
use generic_array::{
    GenericArray,
    typenum::{U4, U19, U32, U181, U233},
};

pub struct PseudoRandomStreamChaCha32(ChaCha);

impl PseudoRandomStream<U32> for PseudoRandomStreamChaCha32 {
    fn seed(v: GenericArray<u8, U32>) -> Self {
        let mut array = [0; 32];
        array.copy_from_slice(v.as_ref());
        PseudoRandomStreamChaCha32(ChaCha::new_chacha20(&array, &[0u8; 8]))
    }
}

impl KeyStream for PseudoRandomStreamChaCha32 {
    fn xor_read(&mut self, dst: &mut [u8]) -> Result<(), ChaChaError> {
        self.0.xor_read(dst)
    }
}

impl SeekableKeyStream for PseudoRandomStreamChaCha32 {
    fn seek_to(&mut self, byte_offset: u64) -> Result<(), ChaChaError> {
        self.0.seek_to(byte_offset)
    }
}

pub type Sphinx = (SecretKey, Hmac<Sha256>, Sha256, PseudoRandomStreamChaCha32);

/// size = 33 + (19 + 32) * 4 + 32 + 115 = 384 <= 0x1fc
pub type OutgoingInitialPacket = AuthenticatedMessage<Sphinx, U19, U4, GenericArray<u8, U181>>;
/// size = 33 + (19 + 32) * 4 + 32 + 105 + 32 * 4 = 502 <= 0x1fc
pub type IncomingInitialPacket = AuthenticatedMessage<Sphinx, U19, U4, GenericArray<u8, U233>>;
