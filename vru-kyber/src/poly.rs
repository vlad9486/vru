use core::{marker::PhantomData, ops::Not};
use rac::generic_array::{
    GenericArray, ArrayLength,
    sequence::GenericSequence,
    typenum::{self, Bit},
};
use digest::{Update, ExtendableOutput, XofReader};
use super::{
    coefficient::Coefficient,
    size::PolySize,
    poly_inner::{PolyInner, Cbd},
};

pub struct Poly<S, P>
where
    S: PolySize,
    P: Bit,
{
    inner: PolyInner<S>,
    phantom_data: PhantomData<P>,
}

impl<S> Poly<S, typenum::B1>
where
    S: PolySize,
{
    pub fn decompress(b: &GenericArray<u8, S::Compressed>) -> Self {
        Poly {
            inner: PolyInner::decompress(b),
            phantom_data: PhantomData,
        }
    }

    pub fn decompress_slightly(b: &GenericArray<u8, S::CompressedSlightly>) -> Self {
        Poly {
            inner: PolyInner::decompress_slightly(b),
            phantom_data: PhantomData,
        }
    }
}

impl<S> Poly<S, typenum::B1>
where
    S: PolySize,
{
    pub fn get_noise<D, W>(seed: &[u8; 32], nonce: u8) -> Self
    where
        D: Default + Update + ExtendableOutput,
        PolyInner<S>: Cbd<S, W>,
    {
        let mut b = GenericArray::<u8, <PolyInner<S> as Cbd<S, W>>::Eta>::default();

        D::default()
            .chain(seed.as_ref())
            .chain([nonce].as_ref())
            .finalize_xof()
            .read(b.as_mut());

        Poly {
            inner: Cbd::cbd(b),
            phantom_data: PhantomData,
        }
    }

    pub fn to_message(&self) -> GenericArray<u8, S> {
        self.inner.to_message()
    }

    pub fn from_message(message: &GenericArray<u8, S>) -> Self {
        Poly {
            inner: PolyInner::from_message(message),
            phantom_data: PhantomData,
        }
    }
}

impl<S, P> Poly<S, P>
where
    S: PolySize,
    P: Bit + Not,
    <P as Not>::Output: Bit,
{
    pub fn wrap(inner: PolyInner<S>) -> Self {
        Poly {
            inner: inner,
            phantom_data: PhantomData,
        }
    }

    pub fn functor_2_a<F, W, P0, P1>(
        a: &GenericArray<Poly<S, P0>, W>,
        b: &GenericArray<Poly<S, P1>, W>,
        f: F,
    ) -> Self
    where
        F: Fn(GenericArray<Coefficient, W>, GenericArray<Coefficient, W>) -> Coefficient,
        W: ArrayLength<Coefficient> + ArrayLength<Poly<S, P0>> + ArrayLength<Poly<S, P1>>,
        P0: Bit,
        P1: Bit,
    {
        let mut q = GenericArray::default();
        for i in S::c_range() {
            let a = GenericArray::generate(|j| a[j].inner.c[i].clone());
            let b = GenericArray::generate(|j| b[j].inner.c[i].clone());
            q[i] = f(a, b);
        }

        Poly {
            inner: PolyInner { c: q },
            phantom_data: PhantomData,
        }
    }

    pub fn functor_2<F, P0, P1>(a: &Poly<S, P0>, b: &Poly<S, P1>, f: F) -> Self
    where
        F: Fn(&Coefficient, &Coefficient) -> Coefficient,
        P0: Bit,
        P1: Bit,
    {
        let mut q = GenericArray::default();
        for i in S::c_range() {
            q[i] = f(&a.inner.c[i], &b.inner.c[i]);
        }

        Poly {
            inner: PolyInner { c: q },
            phantom_data: PhantomData,
        }
    }

    pub fn functor_3<F, P0, P1, P2>(a: &Poly<S, P0>, b: &Poly<S, P1>, c: &Poly<S, P2>, f: F) -> Self
    where
        F: Fn(&Coefficient, &Coefficient, &Coefficient) -> Coefficient,
        P0: Bit,
        P1: Bit,
        P2: Bit,
    {
        let mut q = GenericArray::default();
        for i in S::c_range() {
            q[i] = f(&a.inner.c[i], &b.inner.c[i], &c.inner.c[i]);
        }

        Poly {
            inner: PolyInner { c: q },
            phantom_data: PhantomData,
        }
    }

    pub fn compress(&self) -> GenericArray<u8, S::Compressed> {
        self.inner.compress()
    }

    pub fn compress_slightly(&self) -> GenericArray<u8, S::CompressedSlightly> {
        self.inner.compress_slightly()
    }

    pub fn to_bytes(&self) -> GenericArray<u8, S::Bytes> {
        self.inner.to_bytes()
    }

    pub fn from_bytes(b: &GenericArray<u8, S::Bytes>) -> Self {
        Poly {
            inner: PolyInner::from_bytes(b),
            phantom_data: PhantomData,
        }
    }

    fn ntt_inner(
        &self,
        zetas: GenericArray<Coefficient, S::C>,
        omegas_inv_bit_rev_montgomery: GenericArray<Coefficient, S::Omegas>,
        psis_inv_montgomery: GenericArray<Coefficient, S::C>,
    ) -> Poly<S, <P as Not>::Output> {
        let mut s = self.inner.clone();
        let p = s.c.as_mut();
        // binary logarithm of S::C
        let l = 64 - ((S::c_range().len() - 1) as u64).leading_zeros();
        if P::BOOL {
            let mut k = 1;
            for level in (0..l).rev() {
                for start in S::c_range().step_by(2 * (1 << level)) {
                    let zeta = zetas[k].0;
                    k += 1;

                    for j in start..(start + (1 << level)) {
                        let t = Coefficient::montgomery_reduce(
                            u32::from(zeta) * u32::from(p[j + (1 << level)].0),
                        );

                        p[j + (1 << level)] =
                            Coefficient::barrett_reduce(p[j].0 + 4 * Coefficient::Q - t.0);
                        if level & 1 != 0 {
                            p[j] = Coefficient(p[j].0 + t.0);
                        } else {
                            p[j] += &t;
                        }
                    }
                }
            }
        } else {
            for level in 0..l {
                for start in 0..(1 << level) {
                    let r = start..(S::c_range().len() - 1);
                    for (jt, j) in r.step_by(2 * (1 << level)).enumerate() {
                        let w = omegas_inv_bit_rev_montgomery[jt].0;
                        let tmp = p[j].0;

                        p[j] = if level & 1 != 0 {
                            Coefficient::barrett_reduce(tmp + p[j + (1 << level)].0)
                        } else {
                            Coefficient(tmp + p[j + (1 << level)].0)
                        };

                        let t = u32::from(w)
                            * (u32::from(tmp) + 4 * (Coefficient::Q as u32)
                                - u32::from(p[j + (1 << level)].0));
                        p[j + (1 << level)] = Coefficient::montgomery_reduce(t);
                    }
                }
            }
            for j in S::c_range() {
                p[j] = Coefficient::montgomery_reduce(
                    u32::from(p[j].0) * u32::from(psis_inv_montgomery[j].0),
                );
            }
        }

        Poly {
            inner: s,
            phantom_data: PhantomData,
        }
    }
}

pub trait Ntt {
    type Output: Ntt;

    fn ntt(&self) -> Self::Output;
}

// TODO: derive macro
impl<P> Ntt for Poly<typenum::U32, P>
where
    P: Bit + Not,
    <P as Not>::Output: Bit + Not<Output = P>,
{
    type Output = Poly<typenum::U32, <P as Not>::Output>;

    fn ntt(&self) -> Self::Output {
        const OMEGAS_INV_BIT_REV_MONTGOMERY: [u16; 128] = [
            990, 254, 862, 5047, 6586, 5538, 4400, 7103, 2025, 6804, 3858, 1595, 2299, 4345, 1319,
            7197, 7678, 5213, 1906, 3639, 1749, 2497, 2547, 6100, 343, 538, 7390, 6396, 7418, 1267,
            671, 4098, 5724, 491, 4146, 412, 4143, 5625, 2397, 5596, 6122, 2750, 2196, 1541, 2539,
            2079, 2459, 274, 7524, 6539, 5015, 6097, 7040, 5220, 2716, 1752, 28, 2552, 133, 4441,
            6719, 2298, 6952, 7075, 4672, 5559, 6830, 1442, 2979, 485, 4549, 4224, 6065, 1944, 5,
            1553, 5046, 3436, 4766, 959, 3291, 3684, 6031, 2137, 1597, 2908, 1825, 6132, 98, 1251,
            4306, 4022, 4314, 362, 1289, 5560, 3830, 6724, 6671, 1215, 2281, 4899, 5074, 5988,
            5041, 1883, 2822, 7024, 2920, 594, 6189, 6662, 3247, 771, 5822, 1742, 4206, 3686, 776,
            5987, 8, 4021, 38, 5658, 3017, 6143, 889, 4216,
        ];
        const PSIS_INV_MONTGOMERY: [u16; 256] = [
            1024, 4972, 5779, 6907, 4943, 4168, 315, 5580, 90, 497, 1123, 142, 4710, 5527, 2443,
            4871, 698, 2489, 2394, 4003, 684, 2241, 2390, 7224, 5072, 2064, 4741, 1687, 6841, 482,
            7441, 1235, 2126, 4742, 2802, 5744, 6287, 4933, 699, 3604, 1297, 2127, 5857, 1705,
            3868, 3779, 4397, 2177, 159, 622, 2240, 1275, 640, 6948, 4572, 5277, 209, 2605, 1157,
            7328, 5817, 3191, 1662, 2009, 4864, 574, 2487, 164, 6197, 4436, 7257, 3462, 4268, 4281,
            3414, 4515, 3170, 1290, 2003, 5855, 7156, 6062, 7531, 1732, 3249, 4884, 7512, 3590,
            1049, 2123, 1397, 6093, 3691, 6130, 6541, 3946, 6258, 3322, 1788, 4241, 4900, 2309,
            1400, 1757, 400, 502, 6698, 2338, 3011, 668, 7444, 4580, 6516, 6795, 2959, 4136, 3040,
            2279, 6355, 3943, 2913, 6613, 7416, 4084, 6508, 5556, 4054, 3782, 61, 6567, 2212, 779,
            632, 5709, 5667, 4923, 4911, 6893, 4695, 4164, 3536, 2287, 7594, 2848, 3267, 1911,
            3128, 546, 1991, 156, 4958, 5531, 6903, 483, 875, 138, 250, 2234, 2266, 7222, 2842,
            4258, 812, 6703, 232, 5207, 6650, 2585, 1900, 6225, 4932, 7265, 4701, 3173, 4635, 6393,
            227, 7313, 4454, 4284, 6759, 1224, 5223, 1447, 395, 2608, 4502, 4037, 189, 3348, 54,
            6443, 2210, 6230, 2826, 1780, 3002, 5995, 1955, 6102, 6045, 3938, 5019, 4417, 1434,
            1262, 1507, 5847, 5917, 7157, 7177, 6434, 7537, 741, 4348, 1309, 145, 374, 2236, 4496,
            5028, 6771, 6923, 7421, 1978, 1023, 3857, 6876, 1102, 7451, 4704, 6518, 1344, 765, 384,
            5705, 1207, 1630, 4734, 1563, 6839, 5933, 1954, 4987, 7142, 5814, 7527, 4953, 7637,
            4707, 2182, 5734, 2818, 541, 4097, 5641,
        ];
        const ZETAS: [u16; 256] = [
            990, 7427, 2634, 6819, 578, 3281, 2143, 1095, 484, 6362, 3336, 5382, 6086, 3823, 877,
            5656, 3583, 7010, 6414, 263, 1285, 291, 7143, 7338, 1581, 5134, 5184, 5932, 4042, 5775,
            2468, 3, 606, 729, 5383, 962, 3240, 7548, 5129, 7653, 5929, 4965, 2461, 641, 1584,
            2666, 1142, 157, 7407, 5222, 5602, 5142, 6140, 5485, 4931, 1559, 2085, 5284, 2056,
            3538, 7269, 3535, 7190, 1957, 3465, 6792, 1538, 4664, 2023, 7643, 3660, 7673, 1694,
            6905, 3995, 3475, 5939, 1859, 6910, 4434, 1019, 1492, 7087, 4761, 657, 4859, 5798,
            2640, 1693, 2607, 2782, 5400, 6466, 1010, 957, 3851, 2121, 6392, 7319, 3367, 3659,
            3375, 6430, 7583, 1549, 5856, 4773, 6084, 5544, 1650, 3997, 4390, 6722, 2915, 4245,
            2635, 6128, 7676, 5737, 1616, 3457, 3132, 7196, 4702, 6239, 851, 2122, 3009, 7613,
            7295, 2007, 323, 5112, 3716, 2289, 6442, 6965, 2713, 7126, 3401, 963, 6596, 607, 5027,
            7078, 4484, 5937, 944, 2860, 2680, 5049, 1777, 5850, 3387, 6487, 6777, 4812, 4724,
            7077, 186, 6848, 6793, 3463, 5877, 1174, 7116, 3077, 5945, 6591, 590, 6643, 1337, 6036,
            3991, 1675, 2053, 6055, 1162, 1679, 3883, 4311, 2106, 6163, 4486, 6374, 5006, 4576,
            4288, 5180, 4102, 282, 6119, 7443, 6330, 3184, 4971, 2530, 5325, 4171, 7185, 5175,
            5655, 1898, 382, 7211, 43, 5965, 6073, 1730, 332, 1577, 3304, 2329, 1699, 6150, 2379,
            5113, 333, 3502, 4517, 1480, 1172, 5567, 651, 925, 4573, 599, 1367, 4109, 1863, 6929,
            1605, 3866, 2065, 4048, 839, 5764, 2447, 2022, 3345, 1990, 4067, 2036, 2069, 3567,
            7371, 2368, 339, 6947, 2159, 654, 7327, 2768, 6676, 987, 2214,
        ];

        let mut zetas = GenericArray::default();
        for (i, x) in ZETAS.iter().enumerate() {
            zetas[i] = Coefficient(*x);
        }
        let mut omegas_inv_bit_rev_montgomery = GenericArray::default();
        for (i, x) in OMEGAS_INV_BIT_REV_MONTGOMERY.iter().enumerate() {
            omegas_inv_bit_rev_montgomery[i] = Coefficient(*x);
        }
        let mut psis_inv_montgomery = GenericArray::default();
        for (i, x) in PSIS_INV_MONTGOMERY.iter().enumerate() {
            psis_inv_montgomery[i] = Coefficient(*x);
        }
        self.ntt_inner(zetas, omegas_inv_bit_rev_montgomery, psis_inv_montgomery)
    }
}
