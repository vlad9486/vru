use serde::{ser, de};
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

pub struct LineLike<T>(pub T)
where
    T: Line;

impl<T> Clone for LineLike<T>
where
    T: Line,
{
    fn clone(&self) -> Self {
        let array = self.0.clone_line();
        LineLike(T::clone_array(&array))
    }
}

impl<T> ser::Serialize for LineLike<T>
where
    T: Line,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        let array = self.0.clone_line();
        array.serialize(serializer)
    }
}

impl<'de, T> de::Deserialize<'de> for LineLike<T>
where
    T: Line,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let array = de::Deserialize::deserialize(deserializer)?;
        Ok(LineLike(T::clone_array(&array)))
    }
}
