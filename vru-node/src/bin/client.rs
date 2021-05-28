use std::{path::PathBuf, net::SocketAddr};
use structopt::StructOpt;
use vru_session::handshake::Identity;

#[derive(StructOpt)]
pub struct Args {
    #[structopt(long)]
    path: PathBuf,
    #[structopt(subcommand)]
    cmd: Cmd,
}

#[derive(StructOpt)]
pub enum Cmd {
    Connect { peer: Identity, address: SocketAddr },
    SendText { peer: Identity, text: String },
}

fn main() {
    use std::os::unix::net::UnixStream;
    use vru_udp::{Command, LocalCommand};

    let Args { path, cmd } = StructOpt::from_args();
    let command = match cmd {
        Cmd::Connect { peer, address } => Command::Connect {
            peer_pi: peer,
            address,
        },
        Cmd::SendText { peer, text } => Command::Local {
            destination: peer,
            command: LocalCommand::SendText(text),
        },
    };

    let path = path.join("ctrl.sock");
    let ctrl = UnixStream::connect(&path)
        .unwrap_or_else(|error| panic!("cannot connect to: {:?}, error: {:?}", path, error));
    bincode::serialize_into(ctrl, &command)
        .unwrap_or_else(|error| panic!("cannot send command to: {:?}, error: {:?}", path, error));
}
