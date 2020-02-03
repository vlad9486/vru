use aead::Aead;
use byteorder::ByteOrder;

pub trait NoiseNonce
where
    Self: Aead,
{
    type Endianness: ByteOrder;
}

#[cfg(any(feature = "chacha20poly1305", test))]
impl NoiseNonce for chacha20poly1305::ChaCha20Poly1305 {
    type Endianness = byteorder::LittleEndian;
}

#[cfg(any(feature = "aes-gcm", test))]
impl NoiseNonce for aes_gcm::Aes256Gcm {
    type Endianness = byteorder::BigEndian;
}
