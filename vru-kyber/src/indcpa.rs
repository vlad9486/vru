use core::{
    convert::TryInto,
    ops::{Mul, Add},
};
use rac::{
    Line, LineValid,
    Concat,
    generic_array::{
        GenericArray, ArrayLength,
        sequence::GenericSequence,
        typenum::{self, Bit, Unsigned},
    },
};
use digest::{Update, FixedOutput, ExtendableOutput, XofReader};
use super::{
    coefficient::Coefficient,
    size::PolySize,
    poly_inner::{PolyInner, Cbd},
    poly::{Poly, Ntt},
};

pub type C = Concat<GenericArray<u8, typenum::U32>, GenericArray<u8, typenum::U32>>;

fn gen_matrix<S, W, T>(seed: &GenericArray<u8, typenum::U32>) -> GenericArray<GenericArray<Poly<S, typenum::B0>, W>, W>
where
    S: PolySize + Unsigned,
    W: ArrayLength<Poly<S, typenum::B0>> + ArrayLength<GenericArray<Poly<S, typenum::B0>, W>>,
    T: Bit,
{
    use sha3::Shake128;
    const SHAKE128_RATE: usize = 168;

    GenericArray::generate(|i| {
        GenericArray::generate(|j| {
            let mut buf = [0; SHAKE128_RATE * 4];
            let sep = if T::BOOL {
                [i as u8, j as u8]
            } else {
                [j as u8, i as u8]
            };
            let mut xof = Shake128::default().chain(seed).chain(&sep).finalize_xof();
            xof.read(buf.as_mut());

            let (mut n_blocks, mut pos, mut ctr) = (4, 0, 0);
            let mut c = GenericArray::default();

            while ctr < S::C::USIZE {
                let val = u16::from_le_bytes(buf[pos..(pos + 2)].try_into().unwrap()) & 0x1fff;
                if val < Coefficient::Q {
                    c[ctr] = Coefficient(val);
                    ctr += 1;
                }
                pos += 2;

                if pos > SHAKE128_RATE * n_blocks - 2 {
                    n_blocks = 1;
                    xof.read(&mut buf);
                    pos = 0;
                }
            }

            Poly::wrap(PolyInner { c: c })
        })
    })
}

pub struct SecretKey<S, W>
where
    S: PolySize,
    W: ArrayLength<Poly<S, typenum::B0>>,
{
    poly_vector: GenericArray<Poly<S, typenum::B0>, W>,
}

#[derive(Clone)]
pub struct PublicKey<S, W>
where
    S: PolySize,
    W: ArrayLength<Poly<S, typenum::B1>>,
{
    poly_vector: GenericArray<Poly<S, typenum::B1>, W>,
    public_seed: GenericArray<u8, typenum::U32>,
}

pub struct CipherText<S, W>
where
    S: PolySize,
    W: ArrayLength<Poly<S, typenum::B1>>,
{
    poly_vector: GenericArray<Poly<S, typenum::B1>, W>,
    poly: Poly<S, typenum::B1>,
}

pub fn key_pair<S, W>(seed: &GenericArray<u8, typenum::U32>) -> (SecretKey<S, W>, PublicKey<S, W>)
where
    S: PolySize,
    W: ArrayLength<GenericArray<Poly<S, typenum::B0>, W>>,
    W: ArrayLength<Poly<S, typenum::B0>>,
    W: ArrayLength<Poly<S, typenum::B1>>,
    W: ArrayLength<Coefficient>,
    PolyInner<S>: Cbd<S, W>,
    Poly<S, typenum::B1>: Ntt<Output = Poly<S, typenum::B0>>,
    Poly<S, typenum::B0>: Ntt<Output = Poly<S, typenum::B1>>,
{
    use sha3::{Sha3_512, Shake256};

    let c = Sha3_512::default().chain(seed).finalize_fixed();
    let Concat(public_seed, noise_seed) = C::clone_array(&c);

    let matrix = gen_matrix::<S, W, typenum::B0>(&public_seed);
    let sk = GenericArray::generate(|i| Poly::get_noise::<Shake256, W>(&noise_seed, i as u8).ntt());

    let e: GenericArray<Poly<S, typenum::B1>, W> = GenericArray::generate(|i| {
        let i = i + W::USIZE;
        Poly::get_noise::<Shake256, W>(&noise_seed, i as u8)
    });

    let pk = GenericArray::generate(|i| {
        let p: Poly<S, typenum::B0> = Poly::functor_2_a(&sk, &matrix[i], |a, b| {
            Coefficient::acc(a.iter().zip(b.iter()))
        });
        let p = p.ntt();
        Poly::functor_2(&p, &e[i], |p, e| p + e)
    });

    (
        SecretKey { poly_vector: sk },
        PublicKey {
            poly_vector: pk,
            public_seed: public_seed,
        },
    )
}

pub fn encapsulate<S, W>(
    noise_seed: &GenericArray<u8, typenum::U32>,
    message: &GenericArray<u8, S>,
    public_key: &PublicKey<S, W>,
) -> CipherText<S, W>
where
    S: PolySize,
    W: ArrayLength<GenericArray<Poly<S, typenum::B0>, W>>,
    W: ArrayLength<Poly<S, typenum::B0>>,
    W: ArrayLength<Poly<S, typenum::B1>>,
    W: ArrayLength<Coefficient>,
    PolyInner<S>: Cbd<S, W>,
    Poly<S, typenum::B1>: Ntt<Output = Poly<S, typenum::B0>>,
    Poly<S, typenum::B0>: Ntt<Output = Poly<S, typenum::B1>>,
{
    use sha3::Shake256;

    let matrix = gen_matrix::<S, W, typenum::B1>(&public_key.public_seed);
    let sp = GenericArray::generate(|i| Poly::get_noise::<Shake256, W>(noise_seed, i as u8).ntt());

    let ep: GenericArray<Poly<S, typenum::B1>, W> = GenericArray::generate(|i| {
        let i = i + W::USIZE;
        Poly::get_noise::<Shake256, W>(noise_seed, i as u8)
    });

    let bp = GenericArray::generate(|i| {
        let t: Poly<S, typenum::B0> = Poly::functor_2_a(&sp, &matrix[i], |a, b| {
            Coefficient::acc(a.iter().zip(b.iter()))
        });
        let t = t.ntt();
        Poly::functor_2(&t, &ep[i], |p, e| p + e)
    });

    let ntt_pk = GenericArray::generate(|i| public_key.poly_vector[i].ntt());
    let v: Poly<S, typenum::B0> = Poly::functor_2_a(&ntt_pk, &sp, |a, b| {
        Coefficient::acc(a.iter().zip(b.iter()))
    });
    let v = v.ntt();

    let epp = Poly::get_noise::<Shake256, W>(noise_seed, 2 * (W::USIZE as u8));
    let k = Poly::from_message(message);

    let v = Poly::functor_3(&v, &k, &epp, |v, k, epp| &(v + epp) + k);

    CipherText {
        poly_vector: bp,
        poly: v,
    }
}

pub fn decapsulate<S, W>(
    cipher_text: &CipherText<S, W>,
    secret_key: &SecretKey<S, W>,
) -> GenericArray<u8, S>
where
    S: PolySize,
    W: ArrayLength<Poly<S, typenum::B0>>,
    W: ArrayLength<Poly<S, typenum::B1>>,
    W: ArrayLength<Coefficient>,
    Poly<S, typenum::B1>: Ntt<Output = Poly<S, typenum::B0>>,
    Poly<S, typenum::B0>: Ntt<Output = Poly<S, typenum::B1>>,
{
    let bp = GenericArray::generate(|i| cipher_text.poly_vector[i].ntt());
    let mp: Poly<S, typenum::B0> = Poly::functor_2_a(&secret_key.poly_vector, &bp, |a, b| {
        Coefficient::acc(a.iter().zip(b.iter()))
    });

    Poly::functor_2(&mp.ntt(), &cipher_text.poly, |mp, v| mp - v).to_message()
}

impl<S, W> LineValid for SecretKey<S, W>
where
    S: PolySize,
    W: ArrayLength<Poly<S, typenum::B0>> + Mul<S::Bytes>,
    <W as Mul<S::Bytes>>::Output: ArrayLength<u8>,
{
    type Length = <W as Mul<S::Bytes>>::Output;

    fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
        let mut it = a
            .as_slice()
            .chunks(S::Bytes::USIZE)
            .map(|slice| Poly::from_bytes(GenericArray::from_slice(slice)));

        Ok(SecretKey {
            poly_vector: GenericArray::generate(|_| it.next().unwrap()),
        })
    }

    fn clone_line(&self) -> GenericArray<u8, Self::Length> {
        let mut buffer = GenericArray::default();
        buffer
            .as_mut_slice()
            .chunks_mut(S::Bytes::USIZE)
            .zip(self.poly_vector.iter())
            .for_each(|(slice, poly)| slice.clone_from_slice(poly.to_bytes().as_ref()));

        buffer
    }
}

impl<S, W> Line for SecretKey<S, W>
where
    S: PolySize,
    W: ArrayLength<Poly<S, typenum::B0>>,
    SecretKey<S, W>: LineValid,
{
    fn clone_array(a: &GenericArray<u8, Self::Length>) -> Self {
        Self::try_clone_array(a).unwrap()
    }
}

impl<S, W> LineValid for PublicKey<S, W>
where
    S: PolySize,
    W: ArrayLength<Poly<S, typenum::B1>> + Mul<S::CompressedSlightly>,
    <W as Mul<S::CompressedSlightly>>::Output: Add<typenum::U32>,
    <<W as Mul<S::CompressedSlightly>>::Output as Add<typenum::U32>>::Output: ArrayLength<u8>,
{
    type Length = <<W as Mul<S::CompressedSlightly>>::Output as Add<typenum::U32>>::Output;

    fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
        let mut it = a
            .as_slice()
            .chunks(S::CompressedSlightly::USIZE)
            .map(|slice| Poly::decompress_slightly(GenericArray::from_slice(slice)));
        let pos = S::CompressedSlightly::USIZE * W::USIZE;
        let mut seed = GenericArray::default();
        seed.clone_from_slice(&a[pos..]);

        Ok(PublicKey {
            poly_vector: GenericArray::generate(|_| it.next().unwrap()),
            public_seed: seed,
        })
    }

    fn clone_line(&self) -> GenericArray<u8, Self::Length> {
        let mut buffer = GenericArray::default();
        buffer
            .as_mut_slice()
            .chunks_mut(S::CompressedSlightly::USIZE)
            .zip(self.poly_vector.iter())
            .for_each(|(slice, poly)| slice.clone_from_slice(poly.compress_slightly().as_ref()));
        let pos = S::CompressedSlightly::USIZE * W::USIZE;
        buffer[pos..].clone_from_slice(self.public_seed.as_ref());

        buffer
    }
}

impl<S, W> Line for PublicKey<S, W>
where
    S: PolySize,
    W: ArrayLength<Poly<S, typenum::B1>>,
    PublicKey<S, W>: LineValid,
{
    fn clone_array(a: &GenericArray<u8, Self::Length>) -> Self {
        Self::try_clone_array(a).unwrap()
    }
}

impl<S, W> LineValid for CipherText<S, W>
where
    S: PolySize,
    W: ArrayLength<Poly<S, typenum::B1>> + Mul<S::CompressedSlightly>,
    <W as Mul<S::CompressedSlightly>>::Output: Add<S::Compressed>,
    <<W as Mul<S::CompressedSlightly>>::Output as Add<S::Compressed>>::Output: ArrayLength<u8>,
{
    type Length = <<W as Mul<S::CompressedSlightly>>::Output as Add<S::Compressed>>::Output;

    fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
        let mut it = a
            .as_slice()
            .chunks(S::CompressedSlightly::USIZE)
            .map(|slice| Poly::decompress_slightly(GenericArray::from_slice(slice)));
        let pos = S::CompressedSlightly::USIZE * W::USIZE;
        let v = Poly::decompress(GenericArray::from_slice(&a[pos..]));
        Ok(CipherText {
            poly_vector: GenericArray::generate(|_| it.next().unwrap()),
            poly: v,
        })
    }

    fn clone_line(&self) -> GenericArray<u8, Self::Length> {
        let mut buffer = GenericArray::default();
        buffer
            .as_mut_slice()
            .chunks_mut(S::CompressedSlightly::USIZE)
            .zip(self.poly_vector.iter())
            .for_each(|(slice, poly)| slice.clone_from_slice(poly.compress_slightly().as_ref()));
        let pos = S::CompressedSlightly::USIZE * W::USIZE;
        buffer[pos..].clone_from_slice(self.poly.compress().as_ref());

        buffer
    }
}

impl<S, W> Line for CipherText<S, W>
where
    S: PolySize,
    W: ArrayLength<Poly<S, typenum::B1>>,
    CipherText<S, W>: LineValid,
{
    fn clone_array(a: &GenericArray<u8, Self::Length>) -> Self {
        Self::try_clone_array(a).unwrap()
    }
}
