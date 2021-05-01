use aead::{NewAead, AeadInPlace};
use byteorder::ByteOrder;
use super::hash::{MixHash, HkdfSplitExt};

pub trait Config {
    type ByteOrder: ByteOrder; // LittleEndian for chacha20poly1305 and BigEndian for Aes256Gcm
    type Aead: NewAead + AeadInPlace + Clone;
    type MixHash: MixHash;
    type HkdfSplit: HkdfSplitExt<Self::Aead, L = <Self::MixHash as MixHash>::L>;
}

impl<D, E, A> Config for (D, E, A)
where
    D: MixHash + HkdfSplitExt<A, L = <D as MixHash>::L>,
    E: ByteOrder,
    A: NewAead + AeadInPlace + Clone,
{
    type ByteOrder = E;
    type Aead = A;
    type MixHash = D;
    type HkdfSplit = D;
}
