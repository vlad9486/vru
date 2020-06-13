#[tokio::test]
#[ignore]
async fn lndg() {
    use crate::{
        NoiseAlgorithm, CipherAlgorithm, HandshakeState, Rotor, AeadKey, ChainingKey, handshakes,
    };
    use super::{InitiatorEphemeral, InitiatorStatic, ResponderStatic};

    use std::net::SocketAddr;
    use generic_array::{
        GenericArray,
        typenum::{U0, U65, B1},
    };
    use tokio::net::TcpStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use secp256k1::{rand, SecretKey, PublicKey};
    use chacha20poly1305::ChaCha20Poly1305;
    use sha2::Sha256;

    type A = (ChaCha20Poly1305, Sha256, PublicKey, B1);
    type R = LightningRotor<<A as NoiseAlgorithm>::CipherAlgorithm>;

    struct LightningRotor<A>(AeadKey<A>)
    where
        A: CipherAlgorithm;

    // TODO: test rotor, send 1000 messages
    impl<A> Rotor<A> for LightningRotor<A>
    where
        A: CipherAlgorithm,
    {
        const INTERVAL: u64 = 1000;

        fn new(key: &AeadKey<A>) -> Self {
            LightningRotor(key.clone())
        }

        fn rotate(&mut self, chaining_key: &mut ChainingKey<A>, key: &mut A::Aead) {
            use aead::NewAead;

            let (chaining_key_, key_) = A::split_2(chaining_key, &self.0);
            *chaining_key = chaining_key_;
            *key = A::Aead::new(key_.clone());
            self.0 = key_;
        }
    }

    type H = handshakes::XK<A, GenericArray<u8, U0>, GenericArray<u8, U0>, GenericArray<u8, U0>>;

    let remote_public_text = "02c6b22d138648a91b80cbac187024dea4d5e583ac51c56aaddf4f5c600f30322f";
    let remote_public_bytes = hex::decode(remote_public_text.as_bytes()).unwrap();
    let remote_public = PublicKey::from_slice(remote_public_bytes.as_slice()).unwrap();
    let mut rng = rand::thread_rng();

    let state = HandshakeState::new("Noise_XK_secp256k1_ChaChaPoly_SHA256", b"lightning")
        .with_secret::<InitiatorEphemeral>(SecretKey::new(&mut rng))
        .with_secret::<InitiatorStatic>(SecretKey::new(&mut rng))
        .with_point::<ResponderStatic>(remote_public);

    let stream = TcpStream::connect("127.0.0.1:9735".parse::<SocketAddr>().unwrap())
        .await
        .unwrap();
    let (mut cipher, mut stream) = state
        .handshake::<H, _, U65, U0, _, _, _, _, _, _, _, _, R>(
            true,
            stream,
            &mut |mut stream, length| async move {
                let mut buffer = GenericArray::default();
                stream.read_exact(&mut [0]).await?;
                stream.read_exact(&mut buffer[0..length]).await?;
                Ok((buffer, stream))
            },
            &mut |mut stream, length, buffer| async move {
                stream.write_all(&[0]).await?;
                stream.write_all(&buffer[0..length]).await?;
                Ok(stream)
            },
            &mut |_length| async { Ok(GenericArray::default()) },
            &mut |_length, _buffer| async { Ok(()) },
        )
        .await
        .unwrap();

    let mut data = [
        0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let tag = cipher.encrypt(&[], &mut data[0..2]);
    data[2..18].clone_from_slice(tag.as_ref());
    let tag = cipher.encrypt(&[], &mut data[18..25]);
    data[25..41].clone_from_slice(tag.as_ref());
    stream.write_all(data.as_ref()).await.unwrap();

    let mut buffer = [0; 0x10000];
    stream.read(buffer.as_mut()).await.unwrap();
}
