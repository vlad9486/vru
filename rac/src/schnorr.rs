use generic_array::GenericArray;
use digest::{FixedOutput, Update};
use core::marker::PhantomData;
use crate::{
    line::{Array, LineValid},
    concat::Concat,
    elliptic::{Scalar, Curve},
};

pub trait Signature
where
    Self: LineValid,
{
    type Scalar: Scalar;

    type Curve: Curve<Scalar = Self::Scalar>;

    fn sign<M>(secret_key: &Self::Scalar, message: &M, seed: &Self::Scalar) -> Result<Self, ()>
    where
        M: AsRef<[u8]>;

    fn verify<M>(&self, public_key: &Self::Curve, message: &M) -> Result<(), ()>
    where
        M: AsRef<[u8]>;
}

#[derive(Debug, Clone)]
pub struct Schnorr<C, D>
where
    C: Curve,
    D: Default + Update + FixedOutput<OutputSize = <C::Scalar as LineValid>::Length>,
    Concat<Array<C::CoordinateLength>, C::Scalar>: LineValid,
{
    r: Array<C::CoordinateLength>,
    s: C::Scalar,
    phantom_data: PhantomData<D>,
}

impl<C, D> LineValid for Schnorr<C, D>
where
    C: Curve,
    D: Default + Update + FixedOutput<OutputSize = <C::Scalar as LineValid>::Length>,
    Concat<Array<C::CoordinateLength>, C::Scalar>: LineValid,
{
    type Length = <Concat<Array<C::CoordinateLength>, C::Scalar> as LineValid>::Length;

    fn try_clone_array(a: &Array<Self::Length>) -> Result<Self, ()> {
        Concat::try_clone_array(a).map(|Concat(r, s)| Schnorr {
            r: r,
            s: s,
            phantom_data: PhantomData,
        })
    }

    fn clone_line(&self) -> Array<Self::Length> {
        use generic_array::typenum::Unsigned;

        let mut x = GenericArray::default();
        let m = <<C::Scalar as LineValid>::Length as Unsigned>::USIZE;
        x[..m].clone_from_slice(self.r.clone_line().as_ref());
        x[m..].clone_from_slice(self.s.clone_line().as_ref());
        x
    }
}

impl<C, D> Signature for Schnorr<C, D>
where
    C: Curve,
    D: Default + Update + FixedOutput<OutputSize = <C::Scalar as LineValid>::Length>,
    Concat<Array<C::CoordinateLength>, C::Scalar>: LineValid,
{
    type Scalar = C::Scalar;
    type Curve = C;

    fn sign<M>(secret_key: &Self::Scalar, message: &M, seed: &Self::Scalar) -> Result<Self, ()>
    where
        M: AsRef<[u8]>,
    {
        let d = secret_key;
        let k = seed;
        let q = C::base().exp_ec(k);
        let r = q.x_coordinate();
        let h = D::default()
            .chain(r.clone_line())
            .chain(message)
            .finalize_fixed();
        let h = LineValid::try_clone_array(&h)?;
        let s = k.sub_ff(&(d.mul_ff(&h)?))?;
        Ok(Schnorr {
            r: r,
            s: s,
            phantom_data: PhantomData,
        })
    }

    fn verify<M>(&self, public_key: &Self::Curve, message: &M) -> Result<(), ()>
    where
        M: AsRef<[u8]>,
    {
        let &Schnorr {
            r: ref r, s: ref s, ..
        } = self;
        let y = public_key;
        let h = D::default()
            .chain(r.clone_line())
            .chain(message)
            .finalize_fixed();
        let h = LineValid::try_clone_array(&h)?;
        let qk = y.exp_ec(&h).mul_ec(&C::base().exp_ec(&s));
        if qk.x_coordinate().eq(r) {
            Ok(())
        } else {
            Err(())
        }
    }
}

#[cfg(all(test, feature = "curve25519-dalek"))]
#[test]
fn signature() {
    use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
    use generic_array::sequence::GenericSequence;

    let seed = Scalar::try_clone_array(&GenericArray::generate(|_| rand::random())).unwrap();
    let sk = Scalar::try_clone_array(&GenericArray::generate(|_| rand::random())).unwrap();
    let pk = EdwardsPoint::base().exp_ec(&sk);

    let message = [1, 2, 3, 4];
    let signature = Schnorr::<EdwardsPoint, sha3::Sha3_256>::sign(&sk, &message, &seed).unwrap();
    signature.verify(&pk, &message).unwrap();
}
