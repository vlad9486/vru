use generic_array::{
    GenericArray,
    typenum::{U32, U33, U64},
};
use secp256k1::{SecretKey, PublicKey, Signature as Secp256k1Signature};
use crate::{Array, LineValid, Scalar, Curve};

impl LineValid for SecretKey {
    type Length = U32;

    fn try_clone_array(a: &Array<Self::Length>) -> Result<Self, ()> {
        SecretKey::from_slice(a.as_slice()).map_err(|_| ())
    }

    fn clone_line(&self) -> Array<Self::Length> {
        GenericArray::from_slice(&self[..]).clone()
    }
}

impl Scalar for SecretKey {
    fn add_ff(&self, rhs: &Self) -> Result<Self, ()> {
        let mut c = self.clone();
        c.add_assign(rhs.clone_line().as_slice()).map_err(|_| ())?;
        Ok(c)
    }

    fn sub_ff(&self, rhs: &Self) -> Result<Self, ()> {
        let _ = rhs;
        unimplemented!()
    }

    fn mul_ff(&self, rhs: &Self) -> Result<Self, ()> {
        let mut c = self.clone();
        c.mul_assign(rhs.clone_line().as_slice()).map_err(|_| ())?;
        Ok(c)
    }

    fn inv_ff(&self) -> Result<Self, ()> {
        unimplemented!()
    }
}

impl LineValid for PublicKey {
    type Length = U64;

    fn try_clone_array(a: &Array<Self::Length>) -> Result<Self, ()> {
        let mut buffer = [0; 65];
        buffer[0] = 4;
        buffer[1..].clone_from_slice(a.as_slice());
        PublicKey::from_slice(buffer.as_ref()).map_err(|_| ())
    }

    fn clone_line(&self) -> Array<Self::Length> {
        let mut a = GenericArray::default();
        a.clone_from_slice(&self.serialize_uncompressed()[1..]);
        a
    }
}

impl Curve for PublicKey {
    type Scalar = SecretKey;
    type CompressedLength = U33;
    type CoordinateLength = U32;

    const NAME: &'static str = "secp256k1";

    fn base() -> Self {
        #[rustfmt::skip]
        let buffer = [
            0x04,
            0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
            0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
            0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
            0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
            0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
            0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
            0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
            0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8,
        ];
        // safe to unwrap, because the constant
        PublicKey::from_slice(buffer.as_ref()).unwrap()
    }

    fn mul_ec(&self, rhs: &Self) -> Self {
        self.combine(rhs).unwrap()
    }

    fn exp_ec(&self, rhs: &Self::Scalar) -> Self {
        use secp256k1::Secp256k1;

        let context = Secp256k1::verification_only();
        let mut c = self.clone();
        // panics if the scalar is zero or greater than the order of the base point
        // safe to unwrap, because the type system guarantee the scalar is valid
        c.mul_assign(&context, rhs.clone_line().as_slice()).unwrap();
        c
    }

    fn decompress(packed: &Array<Self::CompressedLength>) -> Result<Self, ()> {
        PublicKey::from_slice(packed.as_slice()).map_err(|_| ())
    }

    fn compress(&self) -> Array<Self::CompressedLength> {
        let buffer = self.serialize();
        let mut a = GenericArray::default();
        a.clone_from_slice(buffer.as_ref());
        a
    }

    fn x_coordinate(&self) -> Array<Self::CoordinateLength> {
        let buffer = self.serialize();
        let mut a = GenericArray::default();
        a.clone_from_slice(&buffer[1..]);
        a
    }
}

impl LineValid for Secp256k1Signature {
    type Length = U64;

    fn try_clone_array(a: &Array<Self::Length>) -> Result<Self, ()> {
        Secp256k1Signature::from_compact(a.as_slice()).map_err(|_| ())
    }

    fn clone_line(&self) -> Array<Self::Length> {
        let mut a = GenericArray::default();
        a.clone_from_slice(self.serialize_compact().as_ref());
        a
    }
}
