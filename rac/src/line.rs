use generic_array::{GenericArray, ArrayLength, typenum};

pub trait LineValid
where
    Self: Sized,
{
    type Length: ArrayLength<u8>;

    fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()>;
    fn clone_line(&self) -> GenericArray<u8, Self::Length>;
}

pub trait Line
where
    Self: LineValid,
{
    fn clone_array(a: &GenericArray<u8, Self::Length>) -> Self;
}

impl<L> LineValid for GenericArray<u8, L>
where
    L: ArrayLength<u8>,
{
    type Length = L;

    fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
        Ok(a.clone())
    }

    fn clone_line(&self) -> GenericArray<u8, Self::Length> {
        self.clone()
    }
}

impl<L> Line for GenericArray<u8, L>
where
    L: ArrayLength<u8>,
{
    fn clone_array(a: &GenericArray<u8, Self::Length>) -> Self {
        a.clone()
    }
}

impl LineValid for [u8; 0] {
    type Length = typenum::U0;

    fn try_clone_array(_a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
        Ok([])
    }

    fn clone_line(&self) -> GenericArray<u8, Self::Length> {
        GenericArray::default()
    }
}

impl Line for [u8; 0] {
    fn clone_array(_a: &GenericArray<u8, Self::Length>) -> Self {
        []
    }
}
