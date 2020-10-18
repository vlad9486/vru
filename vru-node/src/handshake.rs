use std::io;
use rac::Line;
use vru_transport::protocol::{
    SecretKey, PublicKey, PublicIdentity, State, SimpleRotor, SimpleCipher, Encrypted, Message4,
};
use tokio::net::TcpStream;
use super::utils;

pub async fn outgoing<L>(
    stream: &mut TcpStream,
    sk: &SecretKey,
    pk: &PublicKey,
    peer_pi: &PublicIdentity,
    payload: L,
) -> Result<(PublicKey, SimpleCipher), io::Error>
where
    L: Line,
    Encrypted<L>: Line,
    Message4<L>: Line,
{
    let state = State::new(&peer_pi);
    let (state, message) = state.generate(&mut rand::thread_rng(), &peer_pi);
    utils::write(stream, message).await?;
    let message = utils::read(stream).await?;
    let (state, message) = state
        .generate(message, &mut rand::thread_rng(), sk, pk)
        .map_err(|()| io::Error::new(io::ErrorKind::Other, "Handshake error"))?;
    utils::write(stream, message).await?;
    let message = utils::read(stream).await?;
    let (cipher, peer_pk, message) = state
        .generate::<SimpleRotor, L>(message, payload, sk, peer_pi)
        .map_err(|()| io::Error::new(io::ErrorKind::Other, "Handshake error"))?;
    utils::write(stream, message).await?;

    Ok((peer_pk, cipher))
}

pub async fn incoming<L>(
    stream: &mut TcpStream,
    sk: &SecretKey,
    pk: &PublicKey,
    pi: &PublicIdentity,
) -> Result<(PublicKey, SimpleCipher, L), io::Error>
where
    L: Line,
    Encrypted<L>: Line,
    Message4<L>: Line,
{
    let state = State::new(&pi);
    let message = utils::read(stream).await?;
    let (state, message) = state
        .consume(message, &mut rand::thread_rng(), &sk)
        .map_err(|()| io::Error::new(io::ErrorKind::Other, "Handshake error"))?;
    utils::write(stream, message).await?;
    let message = utils::read(stream).await?;
    let (state, peer_pk, message) = state
        .consume(message, &pk)
        .map_err(|()| io::Error::new(io::ErrorKind::Other, "Handshake error"))?;
    utils::write(stream, message).await?;
    let message = utils::read(stream).await?;
    let (cipher, payload) = state
        .consume::<SimpleRotor, L>(message, &sk)
        .map_err(|()| io::Error::new(io::ErrorKind::Other, "Handshake error"))?;

    Ok((peer_pk, cipher, payload))
}
