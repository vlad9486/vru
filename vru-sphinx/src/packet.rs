use rac::{LineValid, Curve};
use rac::generic_array::{GenericArray, ArrayLength};
use {
    digest::{Update, FixedOutput},
    cipher::{StreamCipher as _, StreamCipherSeek as _},
};
use super::path::{PayloadHmac, Path};
use super::sphinx::{Sphinx, SharedSecret};

pub struct LocalData<A>
where
    A: Curve,
{
    pub shared_secret: SharedSecret<A>,
}

impl<A> LocalData<A>
where
    A: Curve,
{
    pub fn next<B>(secret_key: &A::Scalar, this: &A) -> (Self, A)
    where
        B: Sphinx<AsymmetricKey = A>,
    {
        let shared_secret = B::tau(this.exp_ec(secret_key));
        let blinding = B::blinding(this, &shared_secret);
        let next = this.exp_ec(&blinding);
        (
            LocalData {
                shared_secret: shared_secret,
            },
            next,
        )
    }

    pub fn digest<D>(&self) -> Self
    where
        D: Default + Update + FixedOutput<OutputSize = <<A as Curve>::Scalar as LineValid>::Length>,
    {
        LocalData {
            shared_secret: D::default().chain(&self.shared_secret).finalize_fixed(),
        }
    }
}

pub struct GlobalData<A, N>
where
    A: Curve,
    N: ArrayLength<SharedSecret<A>>,
{
    pub shared_secrets: GenericArray<SharedSecret<A>, N>,
}

impl<A, N> GlobalData<A, N>
where
    A: Curve + Clone,
    A::Scalar: Clone,
    N: ArrayLength<SharedSecret<A>>,
{
    pub fn new<H, B>(session_key: &A::Scalar, path: H) -> (Self, A)
    where
        H: Iterator<Item = B::AsymmetricKey>,
        B: Sphinx<AsymmetricKey = A>,
    {
        use rac::Scalar;

        let public_key = A::base().exp_ec(session_key);

        let initial = (
            GlobalData {
                shared_secrets: GenericArray::default(),
            },
            session_key.clone(),
            public_key.clone(),
        );

        let (s, _, _) = path.enumerate().fold(
            initial,
            |(mut s, mut secret, public), (index, path_point)| {
                let shared_secret = B::tau(path_point.exp_ec(&secret));
                let blinding = B::blinding(&public, &shared_secret);
                // safe to unwrap because the scalar is trusted
                secret = secret.mul_ff(&blinding).unwrap();
                let public = A::base().exp_ec(&secret);

                s.shared_secrets[index] = shared_secret;
                (s, secret, public)
            },
        );

        (s, public_key)
    }

    pub fn digest<D>(&self) -> Self
    where
        D: Default + Update + FixedOutput<OutputSize = <<A as Curve>::Scalar as LineValid>::Length>,
    {
        let mut shared_secrets_array = self.shared_secrets.clone();
        shared_secrets_array
            .as_mut_slice()
            .iter_mut()
            .for_each(|x| *x = D::default().chain(x.as_ref()).finalize_fixed());
        GlobalData {
            shared_secrets: shared_secrets_array,
        }
    }
}

pub enum Processed<B, L, N, P>
where
    B: Sphinx,
    L: ArrayLength<u8>,
    N: ArrayLength<PayloadHmac<L, B::MacLength>>,
    P: AsMut<[u8]>,
{
    Forward {
        data: GenericArray<u8, L>,
        next: AuthenticatedMessage<B, L, N, P>,
    },
    Exit {
        data: GenericArray<u8, L>,
        message: P,
    },
}

pub struct AuthenticatedMessage<B, L, N, P>
where
    B: Sphinx,
    L: ArrayLength<u8>,
    N: ArrayLength<PayloadHmac<L, B::MacLength>>,
    P: AsMut<[u8]>,
{
    routing_info: Path<L, B::MacLength, N>,
    hmac: GenericArray<u8, B::MacLength>,
    message: P,
}

impl<B, L, N, P> AuthenticatedMessage<B, L, N, P>
where
    B: Sphinx,
    L: ArrayLength<u8>,
    N: ArrayLength<PayloadHmac<L, B::MacLength>> + ArrayLength<SharedSecret<B::AsymmetricKey>>,
    P: AsMut<[u8]>,
{
    pub fn new<T, H>(
        data: &GlobalData<B::AsymmetricKey, N>,
        associated_data: T,
        payloads: H,
        message: P,
    ) -> Self
    where
        T: AsRef<[u8]>,
        H: Iterator<Item = GenericArray<u8, L>> + DoubleEndedIterator + ExactSizeIterator,
    {
        use core::iter;

        let &GlobalData {
            shared_secrets: ref shared_secrets,
        } = data;
        let mut hmac = GenericArray::default();
        let mut routing_info = Path::<L, B::MacLength, N>::new();
        let mut message = message;

        let length = payloads.len();
        for i in 0..length {
            let mut s = B::rho(&shared_secrets[i]);
            let size = PayloadHmac::<L, B::MacLength>::size();
            s.seek((size * (Path::<L, B::MacLength, N>::size() - i)) as usize);
            let start = Path::<L, B::MacLength, N>::size() - length;
            routing_info.as_mut()[start..(start + i + 1)]
                .iter_mut()
                .for_each(|x| *x ^= &mut s);
        }

        payloads.enumerate().rev().for_each(|(index, payload)| {
            routing_info.push(PayloadHmac {
                data: payload,
                hmac: hmac.clone(),
            });

            let mut stream = B::rho(&shared_secrets[index]);
            routing_info ^= &mut stream;

            let mut stream = B::pi(&shared_secrets[index]);
            stream.apply_keystream(message.as_mut());

            hmac = B::mu(
                &shared_secrets[index],
                routing_info
                    .as_ref()
                    .iter()
                    .map(|x| iter::once(x.data.as_ref()).chain(iter::once(x.hmac.as_ref())))
                    .flatten()
                    .chain(iter::once(associated_data.as_ref())),
            )
        });

        AuthenticatedMessage {
            routing_info: routing_info,
            hmac: hmac,
            message: message,
        }
    }

    pub fn process<T>(
        self,
        associated_data: T,
        local: &LocalData<B::AsymmetricKey>,
    ) -> Result<Processed<B, L, N, P>, ()>
    where
        T: AsRef<[u8]>,
    {
        use core::iter;

        let (mut routing_info, hmac_received, mut message) =
            (self.routing_info, self.hmac, self.message);

        let hmac = B::mu(
            &local.shared_secret,
            routing_info
                .as_ref()
                .iter()
                .map(|x| iter::once(x.data.as_ref()).chain(iter::once(x.hmac.as_ref())))
                .flatten()
                .chain(iter::once(associated_data.as_ref())),
        );

        if hmac_received != hmac {
            Err(())
        } else {
            let mut stream = B::rho(&local.shared_secret);
            let mut item = routing_info.pop();
            item ^= &mut stream;
            routing_info ^= &mut stream;

            let mut stream = B::pi(&local.shared_secret);
            stream.apply_keystream(message.as_mut());

            let PayloadHmac {
                data: item_data,
                hmac: item_hmac,
            } = item;

            if item_hmac == GenericArray::default() {
                Ok(Processed::Exit {
                    data: item_data,
                    message: message,
                })
            } else {
                let next = AuthenticatedMessage {
                    routing_info: routing_info,
                    hmac: item_hmac,
                    message: message,
                };

                Ok(Processed::Forward {
                    data: item_data,
                    next: next,
                })
            }
        }
    }
}

#[cfg(feature = "serde")]
mod serde_m {
    use rac::generic_array::{GenericArray, ArrayLength};
    use serde::{Serialize, Serializer, Deserialize, Deserializer};
    use core::{marker::PhantomData, fmt};
    use super::{AuthenticatedMessage, Path, PayloadHmac, Sphinx};

    impl<B, L, N, P> Serialize for AuthenticatedMessage<B, L, N, P>
    where
        B: Sphinx,
        L: ArrayLength<u8>,
        N: ArrayLength<PayloadHmac<L, B::MacLength>>,
        P: AsMut<[u8]> + Serialize,
    {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            use serde::ser::SerializeTuple;

            let mut tuple = serializer.serialize_tuple(3)?;
            tuple.serialize_element(&self.routing_info)?;
            tuple.serialize_element(&self.hmac)?;
            tuple.serialize_element(&self.message)?;
            tuple.end()
        }
    }

    impl<'de, B, L, N, P> Deserialize<'de> for AuthenticatedMessage<B, L, N, P>
    where
        B: Sphinx,
        L: ArrayLength<u8>,
        N: ArrayLength<PayloadHmac<L, B::MacLength>>,
        P: AsMut<[u8]> + for<'d> Deserialize<'d>,
    {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            use serde::de::{Visitor, SeqAccess, Error};

            struct V<B, L, N, P>
            where
                B: Sphinx,
                L: ArrayLength<u8>,
                N: ArrayLength<PayloadHmac<L, B::MacLength>>,
                P: AsMut<[u8]> + for<'d> Deserialize<'d>,
            {
                phantom_data: PhantomData<(B, L, N, P)>,
            }

            impl<'de, B, L, N, P> Visitor<'de> for V<B, L, N, P>
            where
                B: Sphinx,
                L: ArrayLength<u8>,
                N: ArrayLength<PayloadHmac<L, B::MacLength>>,
                P: AsMut<[u8]> + for<'d> Deserialize<'d>,
            {
                type Value = AuthenticatedMessage<B, L, N, P>;

                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "bytes")
                }

                fn visit_seq<S>(self, mut sequence: S) -> Result<Self::Value, S::Error>
                where
                    S: SeqAccess<'de>,
                {
                    let p: Path<L, B::MacLength, N> = sequence
                        .next_element()?
                        .ok_or(Error::custom("not enough data"))?;
                    let m: GenericArray<u8, B::MacLength> = sequence
                        .next_element()?
                        .ok_or(Error::custom("not enough data"))?;
                    let ms: P = sequence
                        .next_element()?
                        .ok_or(Error::custom("not enough data"))?;

                    Ok(AuthenticatedMessage {
                        routing_info: p,
                        hmac: m,
                        message: ms,
                    })
                }
            }

            deserializer.deserialize_tuple(
                3,
                V {
                    phantom_data: PhantomData::<(B, L, N, P)>,
                },
            )
        }
    }
}

mod implementations {
    use rac::generic_array::ArrayLength;
    use rac::Curve;
    use core::fmt;
    use super::{AuthenticatedMessage, Sphinx, PayloadHmac, LocalData};

    impl<B, L, N, P> fmt::Debug for AuthenticatedMessage<B, L, N, P>
    where
        B: Sphinx,
        B::AsymmetricKey: fmt::Debug,
        L: ArrayLength<u8>,
        N: ArrayLength<PayloadHmac<L, B::MacLength>>,
        P: fmt::Debug + AsMut<[u8]>,
    {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.debug_struct("Packet")
                .field("routing_info", &self.routing_info)
                .field("hmac", &self.hmac)
                .field("message", &self.message)
                .finish()
        }
    }

    impl<B, L, N, P> PartialEq for AuthenticatedMessage<B, L, N, P>
    where
        B: Sphinx,
        B::AsymmetricKey: PartialEq,
        L: ArrayLength<u8>,
        N: ArrayLength<PayloadHmac<L, B::MacLength>>,
        P: PartialEq + AsMut<[u8]>,
    {
        fn eq(&self, other: &Self) -> bool {
            self.routing_info.eq(&other.routing_info)
                && self.hmac.eq(&other.hmac)
                && self.message.eq(&other.message)
        }
    }

    impl<B, L, N, P> Eq for AuthenticatedMessage<B, L, N, P>
    where
        B: Sphinx,
        B::AsymmetricKey: PartialEq,
        L: ArrayLength<u8>,
        N: ArrayLength<PayloadHmac<L, B::MacLength>>,
        P: PartialEq + AsMut<[u8]>,
    {
    }

    impl<A> fmt::Debug for LocalData<A>
    where
        A: Curve + fmt::Debug,
    {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.debug_struct("LocalStuff")
                .field("shared_secret", &self.shared_secret)
                .finish()
        }
    }

    impl<A> PartialEq for LocalData<A>
    where
        A: Curve + PartialEq,
    {
        fn eq(&self, other: &Self) -> bool {
            self.shared_secret.eq(&other.shared_secret)
        }
    }

    impl<A> Eq for LocalData<A> where A: Curve + PartialEq {}
}
