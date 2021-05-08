#![forbid(unsafe_code)]

mod command;
pub use self::command::{Command, LocalCommand, Event, Error, LocalEvent};

mod global;
pub use self::global::{Node, NodeRef, NodeDisconnected};

mod local;

const DATAGRAM_SIZE: usize = 1280;
