use core::{
    convert::TryInto,
    ops::{Mul, Add},
};
use rac::{
    Line, LineValid,
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

fn gen_matrix<S, W, T>(seed: &[u8; 32]) -> GenericArray<GenericArray<Poly<S, typenum::B0>, W>, W>
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

pub struct PublicKey<S, W>
where
    S: PolySize,
    W: ArrayLength<Poly<S, typenum::B1>>,
{
    poly_vector: GenericArray<Poly<S, typenum::B1>, W>,
    public_seed: [u8; 32],
}

pub struct CipherText<S, W>
where
    S: PolySize,
    W: ArrayLength<Poly<S, typenum::B1>>,
{
    poly_vector: GenericArray<Poly<S, typenum::B1>, W>,
    poly: Poly<S, typenum::B1>,
}

pub fn key_pair<S, W>(seed: &[u8; 32]) -> (SecretKey<S, W>, PublicKey<S, W>)
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

    let seed = Sha3_512::default().chain(seed.as_ref()).finalize_fixed();
    let public_seed = {
        let mut a = [0; 32];
        a.clone_from_slice(&seed[..32]);
        a
    };
    let noise_seed = {
        let mut a = [0; 32];
        a.clone_from_slice(&seed[32..]);
        a
    };

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
    noise_seed: &[u8; 32],
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
    let sp = GenericArray::generate(|i| Poly::get_noise::<Shake256, W>(&noise_seed, i as u8).ntt());

    let ep: GenericArray<Poly<S, typenum::B1>, W> = GenericArray::generate(|i| {
        let i = i + W::USIZE;
        Poly::get_noise::<Shake256, W>(&noise_seed, i as u8)
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

    let epp = Poly::get_noise::<Shake256, W>(&noise_seed, 2 * (W::USIZE as u8));
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
        let mut seed = [0; 32];
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

#[cfg(test)]
mod tests {
    use std::convert::TryInto;
    use rac::{LineValid, Line, generic_array::{GenericArray, ArrayLength, typenum}};
    use sha3::{
        Sha3_256, Sha3_512,
        digest::{Update, FixedOutput},
    };
    use super::{SecretKey, PublicKey, CipherText, Poly, PolyInner, Cbd, Coefficient};
    use super::{key_pair, encapsulate, decapsulate};

    fn indcpa<W>(seed_text: &str, sk_text: &str, pk_text: &str, e_seed_text: &str, ct_text: &str)
    where
        W: ArrayLength<GenericArray<Poly<typenum::U32, typenum::B0>, W>>,
        W: ArrayLength<Poly<typenum::U32, typenum::B0>>,
        W: ArrayLength<Poly<typenum::U32, typenum::B1>>,
        W: ArrayLength<Coefficient>,
        PolyInner<typenum::U32>: Cbd<typenum::U32, W>,
        SecretKey<typenum::U32, W>: LineValid,
        PublicKey<typenum::U32, W>: LineValid,
        CipherText<typenum::U32, W>: LineValid,
    {
        let seed = hex::decode(seed_text).unwrap();
        let seed = seed.as_slice().try_into().unwrap();
        let (sk, pk) = key_pair::<typenum::U32, W>(seed);
        let sk_t = sk.clone_line();
        assert_eq!(sk_text, hex::encode(&sk_t));
        let pk_t = pk.clone_line();
        assert_eq!(pk_text, hex::encode(&pk_t));

        let seed = hex::decode(e_seed_text).unwrap();
        let (seed, m) = {
            let p = Sha3_256::default().chain(seed).finalize_fixed();
            let q = Sha3_256::default().chain(&pk_t).finalize_fixed();
            let pq = Sha3_512::default().chain(&p).chain(&q).finalize_fixed();
            (pq.as_slice()[32..].try_into().unwrap(), p)
        };
        let pk = Line::clone_array(&pk_t);
        let ct = encapsulate(&seed, &m, &pk);
        let ct_t = ct.clone_line();
        assert_eq!(ct_text, hex::encode(ct_t));

        let m_p = decapsulate(&ct, &sk);
        assert_eq!(m, m_p);
    }

    #[test]
    fn indcpa_2() {
        let seed_text = "934d60b35624d740b30a7f227af2ae7c678e4e04e13c5f509eade2b79aea77e2";
        let sk_text = "\
            2ec119e11d6bf4b631b00e17cf0dcd5e1fce7e343cbfa8ab7e08\
            8d8b560f37ae8df5eca8e8a5ad0c1b761ed851eb6c19692719a4\
            6c151842b3492693aaefa176df39f1fe8888f3c3d59ad981728d\
            3b759b640ab042964403fb18b75a12fe45d78c248d2dc4355ced\
            b08eec39104c5d350b84569c18a43b28711bcb3d2f3154c98531\
            a1c071c0b14d22b050740f61870970b0351037d09e3441eb585e\
            4359301837e7e4138eb00f7edcd371738f067d62db0b33830869\
            8f92f5855f847e2c731f020d934b280176e1e4a2a0597517a70e\
            a070545b5f41b8e7a04cde60406697bbf7294ed67e61c9ba7b90\
            3135d1564b4c00cec44e5cf3c531d28c499342c166442ab00de1\
            2a34c1c9d2a1415e3838557d95c55133c8eb332e31c0ae31c709\
            04fd700df3870ddfc68172490535e43f2a9a0ff77e7c8bb984bd\
            f3dacbf8c7ddce74b7a4623bd79733204e8d0d0a3c62df36f67b\
            fe35213f9b2a936e4288bcc6b452c231b832767aa329456612b4\
            6bd79cb0431dc81e3176b4908cc07091ea7194316496ee4243b6\
            d9245b03180f01a9dc415e4514e9971f0fb6ba132d30a25344d2\
            61b4bf8eda4bdb08ffa12e45ea8123acfa33af0b406284ae25b8\
            4f603d80be72faada627c47d918cfc455b84be6aabe7e0f9e835\
            33e6223177224d8a73330aea2a3e8723358659261a314a1bc953\
            0cee8d383c655d6f5618c9c6cccae2bbfe92a7e18aa8151e2b1f\
            84528b288e96fe2dab76f35838878305bbb171f7edc0e0a6b30b\
            cd09537c71f8f76ba6ca23af694890f2f4181e0304f30628a182\
            f8021dbdd28f29b8fe5d64c00980cc328399bc6ee7e8613eae70\
            9c10e404545789688e7342bdba26463044d319db526227116484\
            09c92e1ab89d0d056f8d3f3dbeb82a2e8c4c58b49bcb61260d7d\
            6548117ca8b58c2eb6ad3aca35388186bc406b7376949be6b9ea\
            b9275e9fda49daea5e06bba6da4a061b59a67f44af58d23291af\
            5d5883d104d365287b8373e231302f9d34a28681f99448ebf944\
            d40073b171f184a939c9559b44a8e0590840e56ccf935492fb30\
            fb433c69666349d3af542bc74e88578e34ef3ec39b24b81fcce3\
            e15d927416aad9b551e41076a39b317adcd1421bbd1ccec56ab9\
            7a1c655c9b14d3bfd8890595d3898939305f278352298ace7155\
        ";
        let pk_text = "\
            17561505679effcfc6c0eeba07a070b8dca0ae47e6c2280d7383244c6b0fde49dc429839af497d23c3e073e9\
            d37bd1e00a683fa7497a74ed14d30db66a3690e383823743aa1b29cdf641faad80e73a450095f70f5e0cff42\
            c3f4f3089bf62b4f42d14e6a5a6785d560eb2d57d3ba20e21a6e3cf04001a932850d64957d967f68d4b3afe3\
            80a69e6efa8e9e763c2b346bfca6af4042297d1068857a722abec1fa8cf974fe5442305be55e3f2d5c31fa9d\
            a2f581775d197e3c3611efe697ebcb12c935506b51b0491084b0f260e77c0da86d01b7ae9afb9d62df81e681\
            132e9fb1260bb4a280da7d418088a0437c465eac43c7dfe27aa931a466c9f4f5817a6317e3d2be29b6397149\
            7a3fdff931d203130cbabcdcc1c427820e545bd92f20c1da06f9e1a1e6fc702a76dd73e7614d2935c816b894\
            5cbb80021eed62a74c6558e97010aaf101e6c1e4de642f23fb74a42580ca015cf9f6fa0356abacd966987723\
            598cc6c90d325d0b29cb7ce09e057a824b79369430613f477deaca2e39ec80a85ce6bb06849f43bffcb58a24\
            47fa01176d7347e550487257be11e9caa91e9e08445d9c3602d5bb59d6bcc25939aa1d8cb070c86cbe8ff606\
            ab7ed6e79ac120e7e27550810de69e0a5cf93487e419fed785321b8a539aa9d5d4c4767b3121624c7476ddc8\
            b1c142574dd601938fb805baa8d966dd2d04399f1048299cf3a1c2f5c8829567852cd7ad804ccc484544c0ba\
            d61c03fc7346ad1182908b633f96ae2d507a66833cf4cf2b2206c692cc721225d9a5c43064f59db08bd41ef7\
            4db36e2445a51d76cdd4ad9708a064063d7352a42c14db3a0b36f02adc88dc04581caccfd0069418888ea886\
            6cd2f99ee17ed4f976137f7cc1a80d84104629f423a0702de74e219226b289bc6f60eb9840f655e530a21413\
            f85c20a1e98123bfec1c3896e2aa178a53d2ea7ecbe789306be82fee4d1def3d3209c019ae64f5e7144bfc23\
            b72f9bc85c0a13b9d041586fd583feb12afd5a402dd33b43543f5fa4eb436c8d\
        ";
        let e_seed_text = "bac5ba881dd35c59719670004692d675b83c98db6a0e55800bafeb7e70491bf4";
        let ct_text = "\
            d70380f302ad36c4ca0792737ea6c56dc41a2960d63302826cdc3a3cc32bad4b0152dadb20d4294f666e90e0\
            07ab016ab9c7ebddeb08716222ebbd82a1a30a810ec5ec4e16633f8619f4c1d55718cd322eb925cd4f619ecd\
            85316ff54c40efb0d3ec8e2f7fab58d1620df78ee81b468f8bf8275bc19488cb455e088f84edbdcc6c20a7c3\
            0dcfda2c4f7648086700295016643d8ff33433e97c22ce7be1186ae3c202c866fc974f5eac5c56365070daf7\
            302587c45dd2fc05324d4aa3800221a6bfbf974afca3eea3a4ab3034a3cbceedd6c74838b0dacadec27a40b1\
            041392f9d1ece9d299a1c50bdf91d108ddee9fabf3dbcc2ab7678b7cc7f54558dcf69ea8233bf6175ba38a7f\
            6bff2568ce1f7683cd38839eca48a3ad9d819b42a2132a7d9976431512a23f7f49b923d26bc83a0ddd2322c6\
            6691f6a1adc0b1df19fe693c858de7be128693a4b0aa64660ae332aff43deb3e9f4605442cd06578dd155010\
            98434e173eb91965bfa365c06a059aef8667672bcea8b7b596736691cfa6bb414f618350fa5143f68e620dd0\
            40ee3f4d0d6d8c6e517c6cf4dea5390d2f346ce5e263e479eb3d650da3269ede9b8fcdac832af2b284e93e23\
            adc9c3ed1bbabe0101a5346bffc6f1144d4bda368252432187fcceb5e726c24edfdecefb565af6aa1270bac7\
            411e633f1b4bc479cfa30979b4507dc9c483a628ff314503243da9dd20b2e0c8525835fbb5fc8de37fbd295a\
            fe9d8d50e86703154a4bc1c1553f73112364a8ce2c1f1b9f67fe0dfc47752742c90bb389ffbf950d2e5da669\
            5099b19f5f2eaa8b9099a64b67100b6fa28c28441387c04745d29a224982d4afcdb26c1314752dd51b4dedfb\
            3692e8f0b01ef7e36baf2d6ff7a82607cf57e7df0f81df6bbffe658a487e9dece7a9744cde88760c464cd874\
            952337977f70c4cd6295f90b3279d1f8aa53f68c50edd075f01fb2219bff6814c8ab8d75881c6d6419fbe2ec\
            893033cc9e50f4102d112cd5ed6e08fb7603b669062f436a36f56d4c0a6e7ef0f87371c3a39f66ea67a39015\
            3aac7f318cf925eaea400f1bbecb3301cf0272dd914aa9f0e2e282f09445e23b018c89f09b9ee2084be00d97\
            e4970210aa5060b7\
        ";

        indcpa::<typenum::U2>(seed_text, sk_text, pk_text, e_seed_text, ct_text)
    }
}
