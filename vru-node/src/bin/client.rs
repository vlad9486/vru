use std::{path::PathBuf, net::SocketAddr};
use structopt::StructOpt;
use vru_transport::protocol::PublicIdentity;

#[derive(StructOpt)]
pub struct Args {
    #[structopt(long)]
    path: PathBuf,
    #[structopt(subcommand)]
    cmd: Cmd,
}

#[derive(StructOpt)]
pub enum Cmd {
    Connect {
        peer: PublicIdentity,
        address: SocketAddr,
    },
    SendText {
        peer: PublicIdentity,
        text: String,
    },
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
    let ctrl = UnixStream::connect(&path).expect(&format!("cannot connect to: {:?}", &path));
    bincode::serialize_into(ctrl, &command).expect(&format!("cannot send command to: {:?}", path));
}
