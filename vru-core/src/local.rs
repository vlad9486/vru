use std::net::SocketAddr;
use tokio::{net::TcpStream, sync::mpsc};
use tokio_stream::StreamExt;
use tokio_util::codec::FramedRead;
use vru_transport::protocol::{PublicKey, TrivialCipher};
use super::{
    terminate,
    wire::{Message, MessageDecoder, DecoderError},
    utils::UnboundedReceiverStream,
};

pub enum LocalCommand {
    SendText(String),
}

enum LocalIncomingEvent {
    Command(LocalCommand),
    Message(Result<Message, DecoderError>),
}

#[derive(Debug)]
pub enum LocalOutgoingEvent {
    ReceivedText(String),
}

pub async fn process<F>(
    trx: terminate::Receiver,
    erx: mpsc::UnboundedReceiver<LocalCommand>,
    etx: F,
    stream: TcpStream,
    cipher: TrivialCipher,
    address: SocketAddr,
    peer: PublicKey,
) where
    F: Fn(LocalOutgoingEvent) + Clone + Send + 'static,
{
    let _ = peer;

    let mut trx = trx;

    let mut stream = stream;
    let (nrx, mut ntx) = stream.split();
    let TrivialCipher { mut send, receive } = cipher;

    let erx = UnboundedReceiverStream::new(erx).map(LocalIncomingEvent::Command);
    let nrx = FramedRead::new(nrx, MessageDecoder::new(receive));
    let mut erx = erx.merge(nrx.map(LocalIncomingEvent::Message));

    while let Some(e) = trx.check(erx.next()).await.flatten() {
        match e {
            LocalIncomingEvent::Message(Ok(message)) => match message {
                Message::Arbitrary(bytes) => {
                    let string = String::from_utf8(bytes).unwrap();
                    etx(LocalOutgoingEvent::ReceivedText(string))
                },
                _ => (),
            },
            LocalIncomingEvent::Message(Err(error)) => {
                let _ = error;
                tracing::info!("breaking channel {:?}", address);
                break;
            },
            LocalIncomingEvent::Command(LocalCommand::SendText(string)) => {
                tracing::info!("will send message: {:?}", &string);

                let message = Message::Arbitrary(string.as_bytes().to_vec());

                match message.write(&mut send, &mut ntx).await {
                    Ok(()) => (),
                    Err(error) => {
                        let _ = error;
                        tracing::info!("breaking channel {:?}", address);
                        break;
                    },
                }
            },
        }
    }
}
