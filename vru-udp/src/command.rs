use std::{net::SocketAddr, io};
use serde::{Serialize, Deserialize};
use vru_transport::protocol::{PublicIdentity, PublicKey};

#[derive(Debug, Serialize, Deserialize)]
pub enum Command {
    Connect {
        peer_pi: PublicIdentity,
        address: SocketAddr,
    },
    Local {
        destination: PublicIdentity,
        command: LocalCommand,
    },
}

#[derive(Debug)]
pub enum Event {
    Error(Error),
    Local {
        source: PublicKey,
        local: LocalEvent,
    },
    Info(String),
}

#[derive(Debug)]
pub enum Error {
    ReadSocket(io::Error),
    FrameSize(SocketAddr, usize),
    ConnectionFailed(SocketAddr),
    WriteTo(SocketAddr, io::Error),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum LocalCommand {
    SendText(String),
}

#[derive(Debug)]
pub enum LocalEvent {
    ReceivedText(String),
    HandshakeDone { incoming: bool },
}
