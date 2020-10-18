use std::net::SocketAddr;
use rac::{
    generic_array::{GenericArray, typenum},
};
use tokio::{net::TcpStream, sync::mpsc};
use vru_transport::protocol::{PublicKey, SimpleCipher};
use futures::{
    future::{FutureExt, Either},
    pin_mut, select,
};
use super::{terminate, utils};

pub enum LocalCommand {
    Message(String),
}

pub async fn process(
    trx: terminate::Receiver,
    rx: mpsc::UnboundedReceiver<LocalCommand>,
    stream: TcpStream,
    cipher: SimpleCipher,
    address: SocketAddr,
    peer: PublicKey,
) {
    type NetworkMessage = GenericArray<u8, typenum::U1024>;

    let mut trx = trx;
    let mut rx = rx;
    let mut stream = stream;
    let (mut n_rx, mut n_tx) = stream.split();
    let SimpleCipher {
        mut send,
        mut receive,
    } = cipher;
    let _ = peer;
    loop {
        let command = rx.recv().fuse();
        let message = utils::read_ciphered::<_, NetworkMessage>(&mut receive, &mut n_rx).fuse();
        pin_mut!(command, message);
        let either = select! {
            command = command => Either::Left(command),
            message = message => Either::Right(message),
            _ = trx.should().fuse() => {
                tracing::info!("breaking channel {:?}", address);
                break;
            },
        };
        match either {
            Either::Right(Ok(message)) => {
                let length = message.as_slice().iter().position(|x| x.eq(&0)).unwrap();
                let string = String::from_utf8(message.as_ref()[0..length].to_vec()).unwrap();
                tracing::info!("received message: {:?}", string)
            },
            Either::Right(Err(error)) => {
                let _ = error;
                tracing::info!("breaking channel {:?}", address);
                break;
            },
            Either::Left(Some(LocalCommand::Message(string))) => {
                tracing::info!("will send message: {:?}", &string);

                let bytes = string.as_bytes();
                let mut message = NetworkMessage::default();
                message.as_mut_slice()[..bytes.len()].clone_from_slice(bytes.as_ref());

                match utils::write_ciphered(&mut send, &mut n_tx, message).await {
                    Ok(()) => (),
                    Err(error) => {
                        let _ = error;
                        tracing::info!("breaking channel {:?}", address);
                        break;
                    },
                }
            },
            Either::Left(None) => panic!(),
        }
    }
}
