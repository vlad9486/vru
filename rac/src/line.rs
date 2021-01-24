use generic_array::{GenericArray, ArrayLength, typenum};

pub type Array<N> = GenericArray<u8, N>;

pub trait LineValid
where
    Self: Sized,
{
    type Length: ArrayLength<u8>;

    fn try_clone_array(a: &Array<Self::Length>) -> Result<Self, ()>;
    fn clone_line(&self) -> Array<Self::Length>;
}

pub trait Line
where
    Self: LineValid,
{
    fn clone_array(a: &Array<Self::Length>) -> Self;
}

impl<L> LineValid for Array<L>
where
    L: ArrayLength<u8>,
{
    type Length = L;

    fn try_clone_array(a: &Array<Self::Length>) -> Result<Self, ()> {
        Ok(a.clone())
    }

    fn clone_line(&self) -> Array<Self::Length> {
        self.clone()
    }
}

impl<L> Line for Array<L>
where
    L: ArrayLength<u8>,
{
    fn clone_array(a: &Array<Self::Length>) -> Self {
        a.clone()
    }
}

impl LineValid for [u8; 0] {
    type Length = typenum::U0;

    fn try_clone_array(_a: &Array<Self::Length>) -> Result<Self, ()> {
        Ok([])
    }

    fn clone_line(&self) -> Array<Self::Length> {
        Array::default()
    }
}

impl Line for [u8; 0] {
    fn clone_array(_a: &Array<Self::Length>) -> Self {
        []
    }
}
