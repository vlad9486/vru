use crate::{NoiseAlgorithm, HandshakeState, History, BaseHistory, SimpleRotor};
use super::{InitiatorEphemeral, InitiatorStatic, ResponderEphemeral, ResponderStatic};

use generic_array::GenericArray;

pub struct TestVector<'a> {
    pub name: &'a str,
    pub prologue: &'a [u8],
    pub local_static_hex: &'a str,
    pub local_ephemeral_hex: &'a str,
    pub remote_static_hex: &'a str,
    pub remote_ephemeral_hex: &'a str,
    pub psk_hex: Option<&'a str>,
    pub hash_hex: &'a str,
    pub messages: [(&'a str, &'a str); 6],
}

impl<'a> TestVector<'a> {
    pub fn test<A, H>(self)
    where
        A: NoiseAlgorithm,
        H: History<A>,
        A::Curve: Clone,
    {
        use rac::LineValid;

        fn from_hex<L>(text: &str) -> L
        where
            L: LineValid,
        {
            let mut bytes = GenericArray::default();
            bytes.clone_from_slice(hex::decode(text).unwrap().as_slice());
            L::try_clone_array(&bytes).unwrap()
        }

        let responder = HandshakeState::<A, _>::new(self.name, self.prologue)
            .with_secret::<ResponderEphemeral>(from_hex(self.remote_ephemeral_hex))
            .with_secret::<ResponderStatic>(from_hex(self.remote_static_hex));
        let initiator = HandshakeState::<A, _>::new(self.name, self.prologue)
            .with_secret::<InitiatorEphemeral>(from_hex(self.local_ephemeral_hex))
            .with_secret::<InitiatorStatic>(from_hex(self.local_static_hex))
            .with_point::<ResponderStatic>(responder.point::<ResponderStatic>().clone());

        let (initiator, responder) = if let Some(h) = self.psk_hex {
            (
                initiator.with_psk(from_hex(h)),
                responder.with_psk(from_hex(h)),
            )
        } else {
            (initiator, responder)
        };

        fn f<'a, 'b, A, H>(
            swap: bool,
            initiator: HandshakeState<A, BaseHistory<A>>,
            responder: HandshakeState<A, BaseHistory<A>>,
            messages: &'a [(&'b str, &'b str)],
        ) -> (
            bool,
            HandshakeState<A, H>,
            HandshakeState<A, H>,
            &'a [(&'b str, &'b str)],
        )
        where
            A: NoiseAlgorithm,
            H: History<A>,
        {
            if H::BASE {
                return (
                    swap,
                    HandshakeState::transmute(initiator),
                    HandshakeState::transmute(responder),
                    messages,
                );
            }

            let (swap, initiator, responder, messages) =
                f::<A, H::Inner>(swap, initiator, responder, messages);
            if H::HAS_PAYLOAD {
                let mut array = GenericArray::default();
                array.clone_from_slice(hex::decode(messages[0].0).unwrap().as_slice());
                let output = <H::Output as LineValid>::try_clone_array(&array).unwrap();
                let (initiator, input) = H::give(initiator, output);
                assert_eq!(hex::encode(input.clone_line().as_ref()), messages[0].1);
                let (responder, output) = H::take(responder, input).ok().unwrap();
                assert_eq!(hex::encode(output.clone_line().as_ref()), messages[0].0);
                (!swap, responder, initiator, &messages[1..])
            } else {
                let array = GenericArray::default();
                let output = <H::Output as LineValid>::try_clone_array(&array).unwrap();
                let (initiator, _input) = H::give(initiator, output);
                let output = <H::Output as LineValid>::try_clone_array(&array).unwrap();
                let (responder, _input) = H::give(responder, output);
                (swap, initiator, responder, messages)
            }
        }

        let (swap, initiator, responder, messages) =
            f::<A, H>(false, initiator, responder, self.messages.as_ref());
        assert_eq!(
            hex::encode(initiator.hash().clone_line().as_ref()),
            self.hash_hex
        );
        assert_eq!(
            hex::encode(responder.hash().clone_line().as_ref()),
            self.hash_hex
        );

        let initiator = initiator.cipher::<SimpleRotor<A::CipherAlgorithm>>(!swap);
        let responder = responder.cipher::<SimpleRotor<A::CipherAlgorithm>>(swap);
        let _ = messages.iter().fold(
            (initiator, responder),
            |(mut initiator, mut responder), (plain, encrypted)| {
                let data_len = plain.len() / 2;
                let mut plain = hex::decode(plain).unwrap();
                let mut encrypted = hex::decode(encrypted).unwrap();
                let tag = initiator.encrypt(&[], plain.as_mut_slice());
                plain.resize(data_len + tag.len(), 0);
                plain[data_len..].clone_from_slice(tag.as_ref());
                assert_eq!(hex::encode(&plain), hex::encode(&encrypted));
                responder
                    .decrypt(&[], &mut encrypted.as_mut_slice()[..data_len], &tag)
                    .unwrap();
                (responder, initiator)
            },
        );
    }
}
