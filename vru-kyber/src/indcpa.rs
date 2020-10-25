use core::convert::TryInto;
use rac::generic_array::{
    GenericArray,
    ArrayLength,
    sequence::GenericSequence,
    typenum::{Bit, Unsigned},
};
use digest::{Update, ExtendableOutput, XofReader};
use super::{
    coefficient::Coefficient,
    size::PolySize,
    poly_inner::PolyInner,
};

fn gen_matrix<D, S, W, T>(seed: &[u8; 32]) -> GenericArray<GenericArray<PolyInner<S>, W>, W>
where
    D: Default + Update + ExtendableOutput,
    S: PolySize + Unsigned,
    W: ArrayLength<PolyInner<S>> + ArrayLength<GenericArray<PolyInner<S>, W>>,
    T: Bit,
{
    const SHAKE128_RATE: usize = 168;

    GenericArray::generate(|i| {
        GenericArray::generate(|j| {
            let mut buf = [0; SHAKE128_RATE * 4];
            let sep = if T::BOOL {
                [i as u8, j as u8]
            } else {
                [j as u8, i as u8]
            };
            let mut xof = D::default().chain(seed).chain(&sep).finalize_xof();
            xof.read(buf.as_mut());

            let (mut n_blocks, mut pos, mut ctr) = (4, 0, 0);
            let mut c = GenericArray::default();

            while ctr < S::USIZE {
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

            PolyInner { c: c }
        })
    })
}
