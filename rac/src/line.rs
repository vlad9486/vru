use generic_array::{GenericArray, ArrayLength};

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
