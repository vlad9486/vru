use std::io;
use rac::{Array, Line, Concat};
use vru_transport::protocol::{
    SecretKey, PublicKey, PublicIdentity, TrivialCipher, Encrypted, Noise, xk,
};
use rand::Rng;
use tokio::net::TcpStream;
use super::utils;

pub async fn outgoing<L>(
    stream: &mut TcpStream,
    sk: &SecretKey,
    pk: &PublicKey,
    peer_pi: &PublicIdentity,
    payload: L,
) -> Result<(PublicKey, TrivialCipher), io::Error>
where
    L: Line,
    Encrypted<Noise, L>: Line,
    xk::Message4<L>: Line,
{
    let mut seed96 = Array::default();
    let mut seed32 = Array::default();

    let state = xk::State::new(&peer_pi);
    rand::thread_rng().fill(seed96.as_mut());
    let (state, message) = state
        .generate(&seed96, &peer_pi)
        .map_err(|()| io::Error::new(io::ErrorKind::Other, "Handshake error"))?;
    utils::write(stream, message).await?;
    let message = utils::read(stream).await?;
    rand::thread_rng().fill::<[u8]>(seed32.as_mut());
    let (state, message) = state
        .generate(message, &seed32, sk, pk)
        .map_err(|()| io::Error::new(io::ErrorKind::Other, "Handshake error"))?;
    utils::write(stream, message).await?;
    let message = utils::read(stream).await?;
    rand::thread_rng().fill::<[u8]>(seed32.as_mut());
    let (cipher, _, peer_pk, message) = state
        .generate::<L, _>(message, &seed32, payload, pk, sk, peer_pi)
        .map_err(|()| io::Error::new(io::ErrorKind::Other, "Handshake error"))?;
    utils::write(stream, message).await?;

    Ok((peer_pk, cipher))
}

pub async fn incoming<L>(
    stream: &mut TcpStream,
    sk: &SecretKey,
    pk: &PublicKey,
    pi: &PublicIdentity,
) -> Result<(PublicKey, TrivialCipher, L), io::Error>
where
    L: Line,
    Encrypted<Noise, L>: Line,
    xk::Message4<L>: Line,
{
    let mut seed96 = Array::default();
    let mut seed32 = Array::default();

    let state = xk::State::new(&pi);
    let message = utils::read(stream).await?;
    rand::thread_rng().fill(seed96.as_mut());
    rand::thread_rng().fill::<[u8]>(seed32.as_mut());
    let (state, message) = state
        .consume(message, &Concat(seed96, seed32), &sk)
        .map_err(|()| io::Error::new(io::ErrorKind::Other, "Handshake error"))?;
    utils::write(stream, message).await?;
    let message = utils::read(stream).await?;
    rand::thread_rng().fill::<[u8]>(seed32.as_mut());
    let (state, peer_pk, message) = state
        .consume(message, &seed32, &pk)
        .map_err(|()| io::Error::new(io::ErrorKind::Other, "Handshake error"))?;
    utils::write(stream, message).await?;
    let message = utils::read(stream).await?;
    let (cipher, _, payload) = state
        .consume::<_, L>(message, pk, &sk)
        .map_err(|()| io::Error::new(io::ErrorKind::Other, "Handshake error"))?;

    Ok((peer_pk, cipher, payload))
}
