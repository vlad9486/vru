#![forbid(unsafe_code)]
#![allow(clippy::type_complexity)]

pub mod handshake;

mod node;
mod processor;

pub use self::node::{Command, Event, NodeDisconnected, NodeRef, Node};
pub use self::processor::{ProcessorFactory, Processor};
