use std::{net::SocketAddr, str::FromStr, sync::Arc, collections::HashMap};
use vru_transport::protocol::{SecretKey, PublicKey, PublicIdentity};
use tokio::{
    sync::mpsc,
    net::{TcpListener, TcpStream, ToSocketAddrs},
    stream::{Stream, StreamExt},
    sync::Mutex,
};
use super::{terminate, handshake, local, utils::TcpListenerStream};

pub enum Command {
    Connect {
        remote_address: SocketAddr,
        peer_pi: PublicIdentity,
    },
    Local {
        command: local::LocalCommand,
        peer_pi: PublicIdentity,
    },
    Terminate,
}

impl FromStr for Command {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut words = s.split_whitespace();
        match words.next().ok_or(())? {
            "connect" => {
                let address = words.next().ok_or(())?.parse().map_err(|_| ())?;
                let peer_pi = words.next().ok_or(())?.parse().map_err(|_| ())?;
                Ok(Command::Connect {
                    remote_address: address,
                    peer_pi: peer_pi,
                })
            },
            "message" => {
                let peer_pi = words.next().ok_or(())?.parse().map_err(|_| ())?;
                let message = words.next().ok_or(())?.to_string();
                Ok(Command::Local {
                    command: local::LocalCommand::SendText(message),
                    peer_pi: peer_pi,
                })
            },
            _ => Err(()),
        }
    }
}

enum IncomingEvent {
    Command(Command),
    Connection((TcpStream, SocketAddr)),
}

pub enum OutgoingEvent {
    Connection {
        peer_pk: PublicKey,
        peer_pi: PublicIdentity,
        address: SocketAddr,
    },
    Event {
        peer_pi: PublicIdentity,
        event: local::LocalOutgoingEvent,
    },
}

impl OutgoingEvent {
    fn connection(peer_pk: &PublicKey, peer_pi: &PublicIdentity, address: &SocketAddr) -> Self {
        OutgoingEvent::Connection {
            peer_pk: peer_pk.clone(),
            peer_pi: peer_pi.clone(),
            address: address.clone(),
        }
    }

    fn local(peer_pi: &PublicIdentity, event: local::LocalOutgoingEvent) -> Self {
        OutgoingEvent::Event {
            peer_pi: peer_pi.clone(),
            event: event,
        }
    }
}

pub async fn run<A, S, F>(sk: SecretKey, pk: PublicKey, local_address: A, erx: S, etx: F)
where
    A: ToSocketAddrs,
    S: Unpin + Stream<Item = Command>,
    F: Fn(OutgoingEvent) + Clone + Send + 'static,
{
    let erx = erx.map(IncomingEvent::Command);

    let listener = match TcpListener::bind(local_address).await {
        Ok(v) => Some(TcpListenerStream::new(v)),
        Err(error) => {
            tracing::error!("failed to start listening: {}", error);
            None
        },
    };

    if let Some(listener) = listener {
        let listener = listener
            .filter_map(|r| {
                if let &Err(ref error) = &r {
                    tracing::error!("failed to accept connection: {}", error);
                }
                r.ok()
            })
            .map(IncomingEvent::Connection);
        global_stream(sk, pk, erx.merge(listener), etx).await;
    } else {
        global_stream(sk, pk, erx, etx).await;
    }
}

type Connections = HashMap<PublicIdentity, mpsc::UnboundedSender<local::LocalCommand>>;

async fn global_stream<S, F>(sk: SecretKey, pk: PublicKey, erx: S, etx: F)
where
    S: Unpin + Stream<Item = IncomingEvent>,
    F: Fn(OutgoingEvent) + Clone + Send + 'static,
{
    let mut trx = terminate::channel_ctrlc();
    let mut erx = erx;
    let connections = Arc::new(Mutex::new(Connections::new()));
    while let Some(event) = trx.check(erx.next()).await.flatten() {
        let connections = connections.clone();
        let (sk, pk) = (sk.clone(), pk.clone());
        let etx = etx.clone();
        match event {
            IncomingEvent::Connection((stream, remote_address)) => {
                trx.spawn(|trx| async move {
                    incoming(sk, pk, stream, remote_address, connections, trx, etx).await
                });
            },
            IncomingEvent::Command(Command::Connect {
                remote_address,
                peer_pi,
            }) => {
                trx.spawn(|trx| async move {
                    outgoing(sk, pk, remote_address, peer_pi, connections, trx, etx).await
                });
            },
            IncomingEvent::Command(Command::Local { command, peer_pi }) => connections
                .lock()
                .await
                .get(&peer_pi)
                .and_then(|c| c.send(command).ok())
                .unwrap_or_else(|| tracing::warn!("connection not found {}", peer_pi)),
            IncomingEvent::Command(Command::Terminate) => break,
        }
    }
}

async fn incoming<F>(
    sk: SecretKey,
    pk: PublicKey,
    stream: TcpStream,
    remote_address: SocketAddr,
    connections: Arc<Mutex<Connections>>,
    trx: terminate::Receiver,
    etx: F,
) where
    F: Fn(OutgoingEvent) + Clone + Send + 'static,
{
    tracing::info!("new incoming connection {}", &remote_address);
    let pi = PublicIdentity::new(&pk);
    let mut stream = stream;
    match handshake::incoming::<[u8; 0]>(&mut stream, &sk, &pk, &pi).await {
        Ok((peer_pk, cipher, _)) => {
            let peer_pi = PublicIdentity::new(&peer_pk);
            etx(OutgoingEvent::connection(
                &peer_pk,
                &peer_pi,
                &remote_address,
            ));
            tracing::info!("post quantum secure connection established {}", &peer_pi);
            let (tx, erx) = mpsc::unbounded_channel();
            connections.lock().await.insert(peer_pi.clone(), tx);
            let etx = move |event| etx(OutgoingEvent::local(&peer_pi, event));
            local::process(trx, erx, etx, stream, cipher, remote_address, peer_pk).await
        },
        Err(error) => tracing::error!("incoming handshake failed {}", error),
    }
}

async fn outgoing<F>(
    sk: SecretKey,
    pk: PublicKey,
    remote_address: SocketAddr,
    peer_pi: PublicIdentity,
    connections: Arc<Mutex<Connections>>,
    trx: terminate::Receiver,
    etx: F,
) where
    F: Fn(OutgoingEvent) + Clone + Send + 'static,
{
    let mut stream = match TcpStream::connect(&remote_address).await {
        Ok(v) => v,
        Err(error) => {
            tracing::error!("failed to connect to {}: {}", &remote_address, error);
            return;
        },
    };
    tracing::info!("new outgoing connection {} {}", &remote_address, &peer_pi);
    match handshake::outgoing(&mut stream, &sk, &pk, &peer_pi, []).await {
        Ok((peer_pk, cipher)) => {
            tracing::info!("post quantum secure connection established {}", &peer_pi);
            etx(OutgoingEvent::connection(
                &peer_pk,
                &peer_pi,
                &remote_address,
            ));
            let (tx, erx) = mpsc::unbounded_channel();
            connections.lock().await.insert(peer_pi.clone(), tx);
            let etx = move |event| etx(OutgoingEvent::local(&peer_pi, event));
            local::process(trx, erx, etx, stream, cipher, remote_address, peer_pk).await
        },
        Err(error) => tracing::error!("outgoing handshake failed {}", error),
    }
}
