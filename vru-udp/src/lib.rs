#![forbid(unsafe_code)]
#![allow(clippy::type_complexity)]

mod command;
pub use self::command::{Command, LocalCommand, Event, Error, LocalEvent};

mod global;
pub use self::global::{Node, NodeRef, NodeDisconnected};

mod local;

mod linkage;

mod session;
pub use self::session::{PublicKey, SecretKey, Identity};

// TODO: use it
pub use self::session::{xx, TrivialCipher, TrivialUnidirectional};
