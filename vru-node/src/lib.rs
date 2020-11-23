#![forbid(unsafe_code)]

mod utils;

mod wire;

mod terminate;

mod handshake;

mod process;
pub use self::process::{LocalCommand, LocalOutgoingEvent};

mod node;
pub use self::node::{run, Command, OutgoingEvent};

#[cfg(test)]
mod tests;
