use std::net::SocketAddr;
use vru_transport::protocol::{SecretKey, PublicKey, PublicIdentity};
use tokio::{sync::mpsc, stream::{Stream, StreamExt}};
use super::{terminate, connection, process};

pub enum Command {
    Listen {
        local_host: SocketAddr,
    },
    Connect {
        remote_host: SocketAddr,
        remote_pi: PublicIdentity,
    },
    Local {
        command: process::LocalCommand,
        peer_pi: PublicIdentity,
    },
}

pub async fn run<S>(ake_sk: SecretKey, ake_pk: PublicKey, control: S)
where
    S: Send + Unpin + Stream<Item = Command> + 'static,
{
    let mut control = control;
    let (c_tx, mut c_rx) = mpsc::unbounded_channel::<connection::Connection>();
    let mut connections = Vec::new();
    let (terminate_sender, mut trx) = terminate::channel();
    while let Some(command) = control.next().await {
        while let Ok(connection) = c_rx.try_recv() {
            connections.push(connection);
        }
        let (sk, pk) = (ake_sk.clone(), ake_pk.clone());
        let c_tx = c_tx.clone();
        match command {
            Command::Listen { local_host } => {
                trx.spawn(|trx| async move {
                    connection::listen(trx, c_tx, sk, pk, local_host).await;
                });
            },
            Command::Connect {
                remote_host,
                remote_pi,
            } => {
                trx.spawn(|trx| async move {
                    connection::connect(trx, c_tx, sk, pk, remote_host, remote_pi).await;
                });
            },
            Command::Local { command, peer_pi } => {
                let connection = connections.iter().find(|c| c.peer_pi.eq(&peer_pi));
                if let Some(connection) = connection {
                    match command {
                        process::LocalCommand::Message(message) => connection
                            .command_sender
                            .send(process::LocalCommand::Message(message))
                            .unwrap_or_else(|_| {
                                tracing::error!("channel not found {}", peer_pi);
                            }),
                    }
                }
            },
        }
    }
    tracing::info!("sending termination event");
    terminate_sender.terminate();
}
