#![forbid(unsafe_code)]

mod utils;

mod wire;

mod terminate;

mod handshake;

mod local;
pub use self::local::{LocalCommand, LocalOutgoingEvent};

mod global;
pub use self::global::{run, Command, OutgoingEvent};

#[cfg(test)]
mod tests;
