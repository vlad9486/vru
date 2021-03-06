use generic_array::{GenericArray, typenum};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE,
    edwards::{EdwardsPoint, CompressedEdwardsY},
    montgomery::MontgomeryPoint,
    scalar::Scalar as C25519Scalar,
};
use crate::{Array, LineValid, Scalar, Curve};

impl LineValid for C25519Scalar {
    type Length = typenum::U32;

    fn try_clone_array(a: &Array<Self::Length>) -> Result<Self, ()> {
        let mut buffer = [0; 32];
        buffer.clone_from_slice(a.as_slice());
        buffer[0] &= 248;
        buffer[31] &= 127;
        buffer[31] |= 64;

        Ok(C25519Scalar::from_bits(buffer))
    }

    fn clone_line(&self) -> Array<Self::Length> {
        GenericArray::from_slice(self.as_bytes()).clone()
    }
}

impl Scalar for C25519Scalar {
    fn add_ff(&self, rhs: &Self) -> Result<Self, ()> {
        Ok(self + rhs)
    }

    fn sub_ff(&self, rhs: &Self) -> Result<Self, ()> {
        Ok(self - rhs)
    }

    fn mul_ff(&self, rhs: &Self) -> Result<Self, ()> {
        Ok(self * rhs)
    }

    fn inv_ff(&self) -> Result<Self, ()> {
        unimplemented!()
    }
}

impl LineValid for MontgomeryPoint {
    type Length = typenum::U32;

    fn try_clone_array(a: &Array<Self::Length>) -> Result<Self, ()> {
        let mut buffer = [0; 32];
        buffer.clone_from_slice(a.as_slice());
        Ok(MontgomeryPoint(buffer))
    }

    fn clone_line(&self) -> Array<Self::Length> {
        GenericArray::from_slice(self.as_bytes()).clone()
    }
}

impl Curve for MontgomeryPoint {
    type Scalar = C25519Scalar;
    type CompressedLength = typenum::U32;
    type CoordinateLength = typenum::U32;

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

    fn decompress(packed: &Array<Self::CompressedLength>) -> Result<Self, ()> {
        Self::try_clone_array(packed)
    }

    fn compress(&self) -> Array<Self::CompressedLength> {
        self.clone_line()
    }

    fn x_coordinate(&self) -> Array<Self::CoordinateLength> {
        unimplemented!()
    }
}

impl LineValid for EdwardsPoint {
    type Length = typenum::U32;

    fn try_clone_array(a: &Array<Self::Length>) -> Result<Self, ()> {
        CompressedEdwardsY::from_slice(a.as_slice())
            .decompress()
            .ok_or(())
    }

    fn clone_line(&self) -> Array<Self::Length> {
        GenericArray::from_slice(self.compress().as_bytes().as_ref()).clone()
    }
}

impl Curve for EdwardsPoint {
    type Scalar = C25519Scalar;
    type CompressedLength = typenum::U32;
    type CoordinateLength = typenum::U32;

    const NAME: &'static str = "25519";

    fn base() -> Self {
        &ED25519_BASEPOINT_TABLE * &C25519Scalar::one()
    }

    fn mul_ec(&self, rhs: &Self) -> Self {
        self + rhs
    }

    fn exp_ec(&self, rhs: &Self::Scalar) -> Self {
        self * rhs
    }

    fn decompress(packed: &Array<Self::CompressedLength>) -> Result<Self, ()> {
        Self::try_clone_array(packed)
    }

    fn compress(&self) -> Array<Self::CompressedLength> {
        self.compress().as_bytes().clone().into()
    }

    fn x_coordinate(&self) -> Array<Self::CoordinateLength> {
        let mut buffer = self.compress().as_bytes().clone();
        buffer[0x1f] &= 0x7f;
        buffer.into()
    }
}
