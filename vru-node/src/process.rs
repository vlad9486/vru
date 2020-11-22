use std::net::SocketAddr;
use tokio::{net::TcpStream, sync::mpsc};
use vru_transport::protocol::{PublicKey, SimpleCipher};
use futures::{
    future::{FutureExt, Either},
    pin_mut, select,
};
use super::{terminate, wire::Message};

pub enum LocalCommand {
    Message(String),
}

#[derive(Debug)]
pub enum LocalEvent {
    _N,
}

pub async fn process<F>(
    trx: terminate::Receiver,
    erx: mpsc::UnboundedReceiver<LocalCommand>,
    etx: F,
    stream: TcpStream,
    cipher: SimpleCipher,
    address: SocketAddr,
    peer: PublicKey,
) where
    F: Fn(LocalEvent) + Clone + Send + 'static,
{
    let mut trx = trx;
    let mut erx = erx;
    let _ = etx;
    let mut stream = stream;
    let (mut n_rx, mut n_tx) = stream.split();
    let SimpleCipher {
        mut send,
        mut receive,
    } = cipher;
    let _ = peer;
    loop {
        let command = erx.recv().fuse();
        let message = Message::read(&mut receive, &mut n_rx).fuse();
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
            Either::Right(Ok(message)) => match message {
                Message::Arbitrary(bytes) => {
                    let string = String::from_utf8(bytes).unwrap();
                    tracing::info!("received message: {:?}", string)
                },
                _ => (),
            },
            Either::Right(Err(error)) => {
                let _ = error;
                tracing::info!("breaking channel {:?}", address);
                break;
            },
            Either::Left(Some(LocalCommand::Message(string))) => {
                tracing::info!("will send message: {:?}", &string);

                let message = Message::Arbitrary(string.as_bytes().to_vec());

                match message.write(&mut send, &mut n_tx).await {
                    Ok(()) => (),
                    Err(error) => {
                        let _ = error;
                        tracing::info!("breaking channel {:?}", address);
                        break;
                    },
                }
            },
            Either::Left(None) => {
                tracing::info!("channel {:?} is broken be the peer", address);
                break;
            },
        }
    }
}
