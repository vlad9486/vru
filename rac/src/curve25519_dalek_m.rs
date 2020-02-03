use crate::{LineValid, Scalar, Curve};

use generic_array::{GenericArray, typenum::U32};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE, montgomery::MontgomeryPoint, scalar::Scalar as C25519Scalar,
};

impl LineValid for C25519Scalar {
    type Length = U32;

    fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
        let mut buffer = [0; 32];
        buffer.clone_from_slice(a.as_slice());
        buffer[0] &= 248;
        buffer[31] &= 127;
        buffer[31] |= 64;

        Ok(C25519Scalar::from_bits(buffer))
    }

    fn clone_line(&self) -> GenericArray<u8, Self::Length> {
        GenericArray::from_slice(self.as_bytes()).clone()
    }
}

impl Scalar for C25519Scalar {
    fn add_ff(&self, rhs: &Self) -> Result<Self, ()> {
        Ok(self + rhs)
    }

    fn mul_ff(&self, rhs: &Self) -> Result<Self, ()> {
        Ok(self * rhs)
    }

    fn inv_ff(&self) -> Result<Self, ()> {
        unimplemented!()
    }
}

impl LineValid for MontgomeryPoint {
    type Length = U32;

    fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
        let mut buffer = [0; 32];
        buffer.clone_from_slice(a.as_slice());
        Ok(MontgomeryPoint(buffer))
    }

    fn clone_line(&self) -> GenericArray<u8, Self::Length> {
        GenericArray::from_slice(self.as_bytes()).clone()
    }
}

impl Curve for MontgomeryPoint {
    type Scalar = C25519Scalar;
    type CompressedLength = U32;

    const NAME: &'static str = "25519";

    fn base() -> Self {
        (&ED25519_BASEPOINT_TABLE * &C25519Scalar::one()).to_montgomery()
    }

    fn mul_ec(&self, rhs: &Self) -> Self {
        let _ = rhs;
        unimplemented!()
    }

    fn exp_ec(&self, rhs: &Self::Scalar) -> Self {
        self * rhs
    }

    fn decompress(packed: &GenericArray<u8, Self::CompressedLength>) -> Result<Self, ()> {
        Self::try_clone_array(packed)
    }

    fn compress(&self) -> GenericArray<u8, Self::CompressedLength> {
        self.clone_line()
    }
}
