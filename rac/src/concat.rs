use core::ops::Add;
use generic_array::{ArrayLength, arr::AddLength};
use crate::line::{Array, LineValid, Line};

pub struct Concat<U, V>(pub U, pub V)
where
    U: LineValid,
    V: LineValid;

impl<U, V> Concat<U, V>
where
    U: LineValid,
    V: LineValid,
{
    pub fn as_ref_u(&self) -> &U {
        &self.0
    }

    pub fn as_ref_v(&self) -> &V {
        &self.1
    }
}

impl<U, V> LineValid for Concat<U, V>
where
    U: LineValid,
    V: LineValid,
    U::Length: Add<V::Length>,
    <U::Length as Add<V::Length>>::Output: ArrayLength<u8>,
{
    type Length = <U::Length as AddLength<u8, V::Length>>::Output;

    fn try_clone_array(a: &Array<Self::Length>) -> Result<Self, ()> {
        use generic_array::typenum::marker_traits::Unsigned;

        let u_length = U::Length::to_usize();
        let v_length = V::Length::to_usize();

        let u_slice = &a[0..u_length];
        let v_slice = &a[u_length..(v_length + u_length)];

        let u = U::try_clone_array(Array::from_slice(u_slice))?;
        let v = V::try_clone_array(Array::from_slice(v_slice))?;

        Ok(Concat(u, v))
    }

    fn clone_line(&self) -> Array<Self::Length> {
        use generic_array::typenum::marker_traits::Unsigned;

        let u_length = U::Length::to_usize();
        let v_length = V::Length::to_usize();

        let u_array = self.0.clone_line();
        let v_array = self.1.clone_line();

        let mut r = Array::default();
        r[0..u_length].clone_from_slice(u_array.as_ref());
        r[u_length..(v_length + u_length)].clone_from_slice(v_array.as_ref());

        r
    }
}

impl<U, V> Line for Concat<U, V>
where
    U: Line,
    V: Line,
    U::Length: Add<V::Length>,
    <U::Length as Add<V::Length>>::Output: ArrayLength<u8>,
{
    fn clone_array(a: &Array<Self::Length>) -> Self {
        use generic_array::typenum::marker_traits::Unsigned;

        let u_length = U::Length::to_usize();
        let v_length = V::Length::to_usize();

        let u_slice = &a[0..u_length];
        let v_slice = &a[u_length..(v_length + u_length)];

        let u = U::clone_array(Array::from_slice(u_slice));
        let v = V::clone_array(Array::from_slice(v_slice));

        Concat(u, v)
    }
}
