use std::{net::SocketAddr, str::FromStr};
use vru_transport::protocol::{SecretKey, PublicKey, PublicIdentity};
use tokio::{sync::mpsc, stream::{Stream, StreamExt}, select, signal::ctrl_c};
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

impl FromStr for Command {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut words = s.split_whitespace();
        match words.next().ok_or(())? {
            "listen" => {
                let address = words.next().ok_or(())?.parse().map_err(|_| ())?;
                Ok(Command::Listen {
                    local_host: address,
                })
            },
            "connect" => {
                let address = words.next().ok_or(())?.parse().map_err(|_| ())?;
                let peer_pi = words.next().ok_or(())?.parse().map_err(|_| ())?;
                Ok(Command::Connect {
                    remote_host: address,
                    remote_pi: peer_pi,
                })
            },
            "message" => {
                let peer_pi = words.next().ok_or(())?.parse().map_err(|_| ())?;
                let message = words.next().ok_or(())?.to_string();
                Ok(Command::Local {
                    command: process::LocalCommand::Message(message),
                    peer_pi: peer_pi,
                })
            },
            _ => Err(()),
        }
    }
}

pub async fn run<S>(ake_sk: SecretKey, ake_pk: PublicKey, mut control: S)
where
    S: Unpin + Stream<Item = Command>,
{
    let (c_tx, mut c_rx) = mpsc::unbounded_channel::<connection::Connection>();
    let mut connections = Vec::new();
    let (terminate_sender, mut trx) = terminate::channel();
    loop {
        let command = select! {
            command = control.next() => match command {
                Some(command) => command,
                None => break,
            },
            _ = ctrl_c() => break,
        };
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
    terminate_sender.terminate();
}
