use std::net::SocketAddr;
use vru_transport::protocol::{SecretKey, PublicKey, PublicIdentity};
use tokio::{task::JoinHandle, sync::mpsc};
use super::{terminate, connection, process};

pub struct Node {
    handle: JoinHandle<()>,
    terminate_sender: terminate::Sender,
    command_sender: mpsc::UnboundedSender<Command>,
}

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

impl Node {
    pub fn run(ake_sk: SecretKey, ake_pk: PublicKey) -> Node {
        let (terminate_sender, mut trx) = terminate::channel();
        let (command_sender, mut command_receiver) = mpsc::unbounded_channel::<Command>();
        let handle = tokio::spawn(async move {
            let (c_tx, mut c_rx) = mpsc::unbounded_channel::<connection::Connection>();
            let mut connections = Vec::new();
            while let Some(command) = trx.check(command_receiver.recv()).await.flatten() {
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
        });

        Node {
            handle: handle,
            terminate_sender: terminate_sender,
            command_sender: command_sender,
        }
    }

    pub fn send(&self, command: Command) -> Result<(), Command> {
        self.command_sender
            .send(command)
            .map_err(|mpsc::error::SendError(command)| command)
    }

    pub fn shutdown(self) {
        match self {
            Node {
                handle,
                terminate_sender,
                command_sender: _,
            } => {
                tracing::info!("sending termination event");
                terminate_sender.terminate();
                futures::executor::block_on(handle).unwrap()
            },
        }
    }
}
