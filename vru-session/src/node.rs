use std::sync::{Arc, atomic::AtomicBool};
use thiserror::Error;
use serde::{Serialize, Deserialize};
use super::{
    handshake::{SecretKey, PublicKey, Identity},
    processor::ProcessorFactory,
};

#[derive(Debug, Error)]
#[error("node disconnected")]
pub struct NodeDisconnected;

#[derive(Debug, Serialize, Deserialize)]
pub enum Command<A> {
    Connect {
        peer_pi: Identity,
        address: A,
    },
    Local {
        destination: Identity,
        command: Vec<u8>,
    },
}

#[derive(Debug)]
pub enum Event<E> {
    Error(E),
    DebugInfo(String),
    Local {
        source: Box<PublicKey>,
        local: Vec<u8>,
    },
}

pub trait NodeRef<E> {
    fn recv(&self) -> Result<Event<E>, NodeDisconnected>;
    fn try_recv(&self) -> Result<Option<Event<E>>, NodeDisconnected>;
}

pub trait Node<P>
where
    Self: Sized,
    P: ProcessorFactory,
{
    type Error;
    type Ref: NodeRef<Self::Error>;
    type Address;

    fn spawn(
        sk: SecretKey,
        pk: PublicKey,
        address: Self::Address,
        processor_factory: P,
        running: Arc<AtomicBool>,
    ) -> Result<(Self, Self::Ref), Self::Error>;

    fn command(&self, command: Command<Self::Address>);

    fn join(self);
}
