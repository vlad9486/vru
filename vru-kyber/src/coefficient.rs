use core::ops::{AddAssign, SubAssign};

#[derive(Default)]
pub struct Coefficient(pub u16);

impl Coefficient {
    pub const Q: u16 = 7681;

    // -inverse_mod(q,2^18)
    const Q_INV: u32 = 7679;
    const R_LOG: u32 = 18;

    pub fn montgomery_reduce(mut a: u32) -> Self {
        let mut u = a.wrapping_mul(Self::Q_INV);
        u &= (1 << Self::R_LOG) - 1;
        u *= Self::Q as u32;
        a += u;
        Coefficient((a >> Self::R_LOG) as u16)
    }

    pub fn barrett_reduce(a: u16) -> Self {
        let mut u = a >> 13;
        u *= Self::Q;
        Coefficient(a - u)
    }

    pub fn freeze(&self) -> u16 {
        let r = Self::barrett_reduce(self.0).0;

        let m = r.wrapping_sub(Self::Q);
        let mut c = m as i16;
        c >>= 15;
        let c = c as u16;
        m ^ ((r ^ m) & c)
    }
}

// TODO: Add, Sub, Mul
impl<'a> AddAssign<&'a Coefficient> for Coefficient {
    fn add_assign(&mut self, rhs: &'a Coefficient) {
        *self = Self::barrett_reduce(self.0 + rhs.0)
    }
}

impl<'a> SubAssign<&'a Coefficient> for Coefficient {
    fn sub_assign(&mut self, rhs: &'a Coefficient) {
        *self = Self::barrett_reduce(self.0 + 3 * Self::Q - rhs.0)
    }
}
