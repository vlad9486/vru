use std::{vec::Vec, string::String, dbg};
use rand::Rng;
use rac::generic_array::GenericArray;
use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
use super::Processed;

mod packet {
    use sha2::Sha256;
    use chacha20::ChaCha20;
    use hmac::Hmac;
    use curve25519_dalek::edwards::EdwardsPoint;
    use crate::AuthenticatedMessage;

    pub type FullSphinx = (EdwardsPoint, Hmac<Sha256>, Sha256, ChaCha20);
    pub type FullPacket<L, N, P> = AuthenticatedMessage<FullSphinx, L, N, P>;
}

use self::packet::{FullSphinx, FullPacket};

#[test]
fn path() {
    use rac::{
        LineValid,
        generic_array::{sequence::GenericSequence, typenum},
    };
    use either::{Left, Right};
    use serde::{Serialize, Serializer};
    use tirse::{DefaultBinarySerializer, WriteWrapper};
    use rac::Curve;
    use core::fmt;
    use super::{LocalData, GlobalData};

    const MESSAGE_LENGTH: usize = 4096 - 319;

    #[derive(Clone)]
    struct Message([u8; MESSAGE_LENGTH]);

    impl Message {
        pub fn new() -> Self {
            let mut array = [0; MESSAGE_LENGTH];
            for i in 0..MESSAGE_LENGTH {
                array[i] = rand::random();
            }
            Message(array)
        }
    }

    impl Eq for Message {}

    impl PartialEq<Self> for Message {
        fn eq(&self, other: &Self) -> bool {
            (0..MESSAGE_LENGTH).fold(true, |a, index| a && self.0[index] == other.0[index])
        }
    }

    impl fmt::Debug for Message {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{:?}", hex::encode(self))
        }
    }

    impl AsRef<[u8]> for Message {
        fn as_ref(&self) -> &[u8] {
            &self.0[..]
        }
    }

    impl AsMut<[u8]> for Message {
        fn as_mut(&mut self) -> &mut [u8] {
            &mut self.0[..]
        }
    }

    impl Serialize for Message {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            use serde::ser::SerializeTuple;

            let mut tuple = serializer.serialize_tuple(MESSAGE_LENGTH)?;
            for i in 0..MESSAGE_LENGTH {
                tuple.serialize_element(&self.0[i])?;
            }
            tuple.end()
        }
    }

    let mut rng = rand::thread_rng();

    let (secrets, path): (Vec<Scalar>, Vec<EdwardsPoint>) = (0..4)
        .map(|_| {
            let secret = Scalar::try_clone_array(&GenericArray::generate(|_| rng.gen())).unwrap();
            let public = EdwardsPoint::base().exp_ec(&secret);
            (secret, public)
        })
        .unzip();

    let payloads = (0..4)
        .map(|_| GenericArray::generate(|_| rand::random::<u8>()))
        .collect::<Vec<_>>();

    let message = Message::new();

    let secret = Scalar::try_clone_array(&GenericArray::generate(|_| rng.gen())).unwrap();
    let (data, public_key) = GlobalData::new::<_, FullSphinx>(&secret, path.into_iter());
    let packet = FullPacket::<typenum::U19, typenum::U5, Message>::new(
        &data,
        &[],
        payloads.clone().into_iter(),
        message.clone(),
    );

    let s = DefaultBinarySerializer::<WriteWrapper<Vec<_>>, String>::new(Vec::new());
    let v = (public_key.compress(), &packet)
        .serialize(s)
        .unwrap()
        .consume()
        .into_inner();

    let initial = (Left(packet), Vec::new(), public_key);
    let (last, output, _) =
        secrets
            .into_iter()
            .fold(initial, |(packet, mut payloads, public_key), secret| {
                let packet = packet.left().unwrap();
                let (local, public_key) = LocalData::next::<FullSphinx>(&secret, &public_key);
                match packet.process(&[], &local).unwrap() {
                    Processed::Forward {
                        data: data,
                        next: next,
                    } => {
                        dbg!(hex::encode(&data));
                        payloads.push(data);
                        (Left(next), payloads, public_key)
                    },
                    Processed::Exit {
                        data: data,
                        message: message,
                    } => {
                        dbg!(hex::encode(&data));
                        dbg!(hex::encode(message.as_ref()));
                        payloads.push(data);
                        (Right(message), payloads, public_key)
                    },
                }
            });

    dbg!(hex::encode(&v));
    assert_eq!(payloads, output);
    assert_eq!(last.right(), Some(message));
    assert_eq!(v.len(), 4096);
}
