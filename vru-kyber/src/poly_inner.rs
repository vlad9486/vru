use core::ops::Mul;
use rac::generic_array::{GenericArray, ArrayLength, typenum};
use super::{coefficient::Coefficient, size::PolySize};

#[derive(Clone)]
pub struct PolyInner<S>
where
    S: PolySize,
{
    pub c: GenericArray<Coefficient, S::C>,
}

impl<S> PolyInner<S>
where
    S: PolySize,
{
    fn from_coefficients(c: GenericArray<Coefficient, S::C>) -> Self {
        PolyInner { c: c }
    }

    pub fn compress_slightly(&self) -> GenericArray<u8, S::CompressedSlightly> {
        let mut t = [0; 8];
        let mut b = GenericArray::default();

        for i in S::range() {
            for j in 0..8 {
                let c = u32::from(Coefficient::freeze(&self.c[8 * i + j]));
                let q = u32::from(Coefficient::Q);
                t[j] = ((((c << 11) + q / 2) / q) & 0x7ff) as u16;
            }

            b[11 * i + 0] = (t[0] & 0xff) as u8;
            b[11 * i + 1] = ((t[0] >> 8) | ((t[1] & 0x1f) << 3)) as u8;
            b[11 * i + 2] = ((t[1] >> 5) | ((t[2] & 0x03) << 6)) as u8;
            b[11 * i + 3] = ((t[2] >> 2) & 0xff) as u8;
            b[11 * i + 4] = ((t[2] >> 10) | ((t[3] & 0x7f) << 1)) as u8;
            b[11 * i + 5] = ((t[3] >> 7) | ((t[4] & 0x0f) << 4)) as u8;
            b[11 * i + 6] = ((t[4] >> 4) | ((t[5] & 0x01) << 7)) as u8;
            b[11 * i + 7] = ((t[5] >> 1) & 0xff) as u8;
            b[11 * i + 8] = ((t[5] >> 9) | ((t[6] & 0x3f) << 2)) as u8;
            b[11 * i + 9] = ((t[6] >> 6) | ((t[7] & 0x07) << 5)) as u8;
            b[11 * i + 10] = (t[7] >> 3) as u8;
        }

        b
    }

    pub fn decompress_slightly(b: &GenericArray<u8, S::CompressedSlightly>) -> Self {
        let mut c = GenericArray::default();

        for i in S::range() {
            let f = |a: u32| Coefficient((((a * u32::from(Coefficient::Q)) + 1024) >> 11) as u16);
            let b = |j| u32::from(b[11 * i + j]);
            c[8 * i + 0] = f(b(0) | ((b(1) & 0x07) << 8));
            c[8 * i + 1] = f((b(1) >> 3) | ((b(2) & 0x3f) << 5));
            c[8 * i + 2] = f((b(2) >> 6) | ((b(3) & 0xff) << 2) | ((b(4) & 0x01) << 10));
            c[8 * i + 3] = f((b(4) >> 1) | ((b(5) & 0x0f) << 7));
            c[8 * i + 4] = f((b(5) >> 4) | ((b(6) & 0x7f) << 4));
            c[8 * i + 5] = f((b(6) >> 7) | ((b(7) & 0xff) << 1) | ((b(8) & 0x03) << 9));
            c[8 * i + 6] = f((b(8) >> 2) | ((b(9) & 0x1f) << 6));
            c[8 * i + 7] = f((b(9) >> 5) | ((b(10) & 0xff) << 3));
        }

        Self::from_coefficients(c)
    }

    pub fn compress(&self) -> GenericArray<u8, S::Compressed> {
        let mut t = [0; 8];
        let mut b = GenericArray::default();

        for i in S::range() {
            for j in 0..8 {
                let c = u32::from(Coefficient::freeze(&self.c[8 * i + j]));
                let q = u32::from(Coefficient::Q);
                t[j] = (((c << 3) + q / 2) / q) & 7;
            }

            b[3 * i + 0] = ((t[0] >> 0) | (t[1] << 3) | (t[2] << 6)) as u8;
            b[3 * i + 1] = ((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7)) as u8;
            b[3 * i + 2] = ((t[5] >> 1) | (t[6] << 2) | (t[7] << 5)) as u8;
        }

        b
    }

    pub fn decompress(b: &GenericArray<u8, S::Compressed>) -> Self {
        let mut c = GenericArray::default();

        for i in S::range() {
            let f = |a: u16| Coefficient(((a * Coefficient::Q) + 4) >> 3);
            let b = |j| u16::from(b[3 * i + j]);
            c[8 * i + 0] = f((b(0) >> 0) & 7);
            c[8 * i + 1] = f((b(0) >> 3) & 7);
            c[8 * i + 2] = f((b(0) >> 6) | ((b(1) << 2) & 4));
            c[8 * i + 3] = f((b(1) >> 1) & 7);
            c[8 * i + 4] = f((b(1) >> 4) & 7);
            c[8 * i + 5] = f((b(1) >> 7) | ((b(2) << 1) & 6));
            c[8 * i + 6] = f((b(2) >> 2) & 7);
            c[8 * i + 7] = f(b(2) >> 5);
        }

        Self::from_coefficients(c)
    }

    pub fn to_bytes(&self) -> GenericArray<u8, S::Bytes> {
        let mut t = [0; 8];
        let mut b = GenericArray::default();

        for i in S::range() {
            for j in 0..8 {
                t[j] = Coefficient::freeze(&self.c[8 * i + j]);
            }

            b[13 * i + 0] = (t[0] & 0xff) as u8;
            b[13 * i + 1] = ((t[0] >> 8) | ((t[1] & 0x07) << 5)) as u8;
            b[13 * i + 2] = ((t[1] >> 3) & 0xff) as u8;
            b[13 * i + 3] = ((t[1] >> 11) | ((t[2] & 0x3f) << 2)) as u8;
            b[13 * i + 4] = ((t[2] >> 6) | ((t[3] & 0x01) << 7)) as u8;
            b[13 * i + 5] = ((t[3] >> 1) & 0xff) as u8;
            b[13 * i + 6] = ((t[3] >> 9) | ((t[4] & 0x0f) << 4)) as u8;
            b[13 * i + 7] = ((t[4] >> 4) & 0xff) as u8;
            b[13 * i + 8] = ((t[4] >> 12) | ((t[5] & 0x7f) << 1)) as u8;
            b[13 * i + 9] = ((t[5] >> 7) | ((t[6] & 0x03) << 6)) as u8;
            b[13 * i + 10] = ((t[6] >> 2) & 0xff) as u8;
            b[13 * i + 11] = ((t[6] >> 10) | ((t[7] & 0x1f) << 3)) as u8;
            b[13 * i + 12] = (t[7] >> 5) as u8;
        }

        b
    }

    pub fn from_bytes(b: &GenericArray<u8, S::Bytes>) -> Self {
        let mut c = GenericArray::default();

        for i in S::range() {
            let b = |j| u16::from(b[13 * i + j]);

            c[8 * i + 0] = Coefficient(b(0) | ((b(1) & 0x1f) << 8));
            c[8 * i + 1] = Coefficient((b(1) >> 5) | (b(2) << 3) | ((b(3) & 0x03) << 11));
            c[8 * i + 2] = Coefficient((b(3) >> 2) | ((b(4) & 0x7f) << 6));
            c[8 * i + 3] = Coefficient((b(4) >> 7) | (b(5) << 1) | ((b(6) & 0x0f) << 9));
            c[8 * i + 4] = Coefficient((b(6) >> 4) | (b(7) << 4) | ((b(8) & 0x01) << 12));
            c[8 * i + 5] = Coefficient((b(8) >> 1) | ((b(9) & 0x3f) << 7));
            c[8 * i + 6] = Coefficient((b(9) >> 6) | (b(10) << 2) | ((b(11) & 0x07) << 10));
            c[8 * i + 7] = Coefficient((b(11) >> 3) | (b(12) << 5));
        }

        Self::from_coefficients(c)
    }

    pub fn to_message(&self) -> GenericArray<u8, S> {
        let mut message = GenericArray::default();
        for (i, b) in message.iter_mut().enumerate() {
            for j in 0..8 {
                let t = (Coefficient::freeze(&self.c[8 * i + j]) << 1)
                    .wrapping_add(Coefficient::Q / 2)
                    .wrapping_div(Coefficient::Q)
                    & 1;
                *b |= (t << j) as u8;
            }
        }
        message
    }

    pub fn from_message(message: &GenericArray<u8, S>) -> Self {
        let mut c = GenericArray::default();
        for (i, b) in message.iter().enumerate() {
            for j in 0..8 {
                let mask = ::core::u16::MIN.wrapping_sub(u16::from(b >> j) & 1);
                c[8 * i + j] = Coefficient(mask & ((Coefficient::Q + 1) / 2));
            }
        }
        Self::from_coefficients(c)
    }
}

pub trait Cbd<S, W>
where
    S: PolySize,
{
    type Eta: ArrayLength<u8>;

    fn cbd(v: GenericArray<u8, Self::Eta>) -> Self;
}

// K = 2 => W = U10
// K = 3 => W = U8
// K = 4 => W = U6
// TODO: impl for U8 and U6
impl<S> Cbd<S, typenum::U2> for PolyInner<S>
where
    S: PolySize + Mul<typenum::U10>,
    <S as Mul<typenum::U10>>::Output: ArrayLength<u8>,
{
    type Eta = <S as Mul<typenum::U10>>::Output;

    fn cbd(b: GenericArray<u8, Self::Eta>) -> Self {
        let mut c = GenericArray::default();

        for i in S::range() {
            for j in 0..2 {
                let mut a = [0; 8];
                a[0..5].clone_from_slice(&b.as_ref()[(5 * (2 * i + j))..(5 * (2 * i + j + 1))]);
                let t = u64::from_le_bytes(a);
                let d = (0..5).map(|j| (t >> j) & 0x08_4210_8421).sum::<u64>();

                for k in 0..4 {
                    let a = (d >> (10 * k)) & 0x1f;
                    let b = (d >> ((10 * k) + 5)) & 0x1f;
                    c[4 * (2 * i + j) + k] = Coefficient((a as u16) + Coefficient::Q - (b as u16));
                }
            }
        }

        Self::from_coefficients(c)
    }
}

impl<S> Cbd<S, typenum::U3> for PolyInner<S>
where
    S: PolySize + Mul<typenum::U8>,
    <S as Mul<typenum::U8>>::Output: ArrayLength<u8>,
{
    type Eta = <S as Mul<typenum::U8>>::Output;

    fn cbd(b: GenericArray<u8, Self::Eta>) -> Self {
        let mut c = GenericArray::default();

        for i in S::range() {
            for j in 0..2 {
                let mut a = [0; 4];
                a.clone_from_slice(&b.as_ref()[(4 * (2 * i + j))..(4 * (2 * i + j + 1))]);
                let t = u32::from_le_bytes(a);
                let d = (0..4).map(|j| (t >> j) & 0x1111_1111).sum::<u32>();

                for k in 0..4 {
                    let a = (d >> (8 * k)) & 0xf;
                    let b = (d >> ((8 * k) + 4)) & 0xf;
                    c[4 * (2 * i + j) + k] = Coefficient((a as u16) + Coefficient::Q - (b as u16));
                }
            }
        }

        Self::from_coefficients(c)
    }
}

impl<S> Cbd<S, typenum::U4> for PolyInner<S>
where
    S: PolySize + Mul<typenum::U6>,
    <S as Mul<typenum::U6>>::Output: ArrayLength<u8>,
{
    type Eta = <S as Mul<typenum::U6>>::Output;

    fn cbd(b: GenericArray<u8, Self::Eta>) -> Self {
        let mut c = GenericArray::default();

        for i in S::range() {
            for j in 0..2 {
                let mut a = [0; 4];
                a[0..3].clone_from_slice(&b.as_ref()[(3 * (2 * i + j))..(3 * (2 * i + j + 1))]);
                let t = u32::from_le_bytes(a);
                let d = (0..3).map(|j| (t >> j) & 0x249249).sum::<u32>();

                for k in 0..4 {
                    let a = (d >> (6 * k)) & 0x7;
                    let b = (d >> ((6 * k) + 3)) & 0x7;
                    c[4 * (2 * i + j) + k] = Coefficient((a as u16) + Coefficient::Q - (b as u16));
                }
            }
        }

        Self::from_coefficients(c)
    }
}
