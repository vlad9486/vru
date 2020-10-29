use core::ops::{AddAssign, SubAssign, Add, Sub};

#[derive(Default, Clone)]
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

    pub fn acc<'a, I>(i: I) -> Self
    where
        I: Iterator<Item = (&'a Self, &'a Self)>,
    {
        let tmp = i
            .map(|(a, b)| {
                let t = Coefficient::montgomery_reduce(4613 * u32::from(b.0));
                Coefficient::montgomery_reduce(u32::from(a.0) * u32::from(t.0)).0
            })
            .sum();

        Coefficient::barrett_reduce(tmp)
    }
}

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

impl<'a, 'b> Add<&'b Coefficient> for &'a Coefficient {
    type Output = Coefficient;

    fn add(self, rhs: &'b Coefficient) -> Self::Output {
        Coefficient::barrett_reduce(self.0 + rhs.0)
    }
}

impl<'a, 'b> Sub<&'b Coefficient> for &'a Coefficient {
    type Output = Coefficient;

    fn sub(self, rhs: &'b Coefficient) -> Self::Output {
        Coefficient::barrett_reduce(self.0 + 3 * Coefficient::Q - rhs.0)
    }
}
