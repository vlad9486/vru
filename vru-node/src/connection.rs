use std::net::SocketAddr;
use vru_transport::protocol::{SecretKey, PublicKey, PublicIdentity};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use super::{terminate, handshake, process};

#[derive(Clone, Debug)]
pub struct Connection {
    pub command_sender: mpsc::UnboundedSender<process::LocalCommand>,
    pub peer_pi: PublicIdentity,
    remote: SocketAddr,
    local: Option<SocketAddr>,
}

pub async fn connect(
    t_rx_connection: terminate::Receiver,
    c_tx_connections: mpsc::UnboundedSender<Connection>,
    ake_sk: SecretKey,
    ake_pk: PublicKey,
    remote_address: SocketAddr,
    peer_pi: PublicIdentity,
) {
    let mut stream = match TcpStream::connect(&remote_address).await {
        Ok(v) => v,
        Err(error) => {
            tracing::error!(
                error = tracing::field::debug(&error),
                "failed to start connect to {}",
                &remote_address,
            );
            return;
        },
    };
    tracing::info!(
        address = tracing::field::display(&remote_address),
        peer = tracing::field::display(&peer_pi),
        "new outgoing connection",
    );
    let (sk, pk) = (ake_sk.clone(), ake_pk.clone());
    let peer_pi = peer_pi.clone();
    match handshake::outgoing(&mut stream, &sk, &pk, &peer_pi, []).await {
        Ok((peer, cipher)) => {
            tracing::info!(
                peer = tracing::field::display(&peer_pi),
                "post quantum secure connection established",
            );
            let (tx, rx) = mpsc::unbounded_channel();
            let connection = Connection {
                peer_pi: peer_pi.clone(),
                command_sender: tx,
                remote: remote_address.clone(),
                local: None,
            };
            match c_tx_connections.send(connection) {
                Ok(()) => (),
                Err(error) => tracing::error!("cannot store incoming connection {}", error),
            }
            process::process(t_rx_connection, rx, stream, cipher, remote_address, peer).await
        },
        Err(error) => tracing::error!(
            error = tracing::field::debug(&error),
            "incoming handshake failed"
        ),
    }
}

pub async fn listen(
    mut t_rx_listening: terminate::Receiver,
    c_tx_connections: mpsc::UnboundedSender<Connection>,
    ake_sk: SecretKey,
    ake_pk: PublicKey,
    local_address: SocketAddr,
) {
    let listener = match TcpListener::bind(&local_address).await {
        Ok(v) => v,
        Err(error) => {
            tracing::error!(
                error = tracing::field::debug(&error),
                "failed to start listening at {}",
                &local_address,
            );
            return;
        },
    };
    tracing::info!("start listening at {}", &local_address);
    let pi = PublicIdentity::new(&ake_pk);
    loop {
        let (mut stream, remote_address) = match t_rx_listening.check(listener.accept()).await {
            Some(Ok(v)) => v,
            Some(Err(error)) => {
                tracing::error!(
                    error = tracing::field::debug(&error),
                    "failed to accept connection at {}",
                    &local_address,
                );
                continue;
            },
            None => {
                tracing::info!("stop listening at {}", &local_address);
                break;
            },
        };
        tracing::info!(
            address = tracing::field::display(&remote_address),
            "new incoming connection"
        );
        let (sk, pk) = (ake_sk.clone(), ake_pk.clone());
        let pi = pi.clone();
        let c_tx_connections = c_tx_connections.clone();
        t_rx_listening.spawn(|t_rx| async move {
            match handshake::incoming::<[u8; 0]>(&mut stream, &sk, &pk, &pi).await {
                Ok((peer, cipher, _)) => {
                    let peer_pi = PublicIdentity::new(&peer);
                    tracing::info!(
                        peer = tracing::field::display(&peer_pi),
                        "post quantum secure connection established",
                    );
                    let (tx, rx) = mpsc::unbounded_channel();
                    let connection = Connection {
                        command_sender: tx,
                        peer_pi: peer_pi.clone(),
                        remote: remote_address.clone(),
                        local: Some(local_address.clone()),
                    };
                    match c_tx_connections.send(connection) {
                        Ok(()) => (),
                        Err(error) => tracing::error!("cannot store incoming connection {}", error),
                    }
                    process::process(t_rx, rx, stream, cipher, remote_address, peer).await
                },
                Err(error) => tracing::error!(
                    error = tracing::field::debug(&error),
                    "incoming handshake failed"
                ),
            }
        });
    }
}
