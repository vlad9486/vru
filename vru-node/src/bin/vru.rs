use std::path::PathBuf;
use structopt::StructOpt;
use vru_node::{Node, Command, LocalCommand};
use vru_transport::protocol::{PublicKey, PublicIdentity};
use tokio::io::{self, AsyncBufReadExt};

#[derive(StructOpt)]
struct Opts {
    #[structopt(long)]
    database: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let opts = Opts::from_args();
    tracing::info!(database = tracing::field::debug(opts.database), "running",);
    let _ = opts.database;

    let (sk, pk) = PublicKey::key_pair(&mut rand::thread_rng());
    let pi = PublicIdentity::new(&pk);
    tracing::info!("identity: {}", pi);

    /*let rt = tokio::runtime::Builder::new_multi_thread();
    rt.enable_all()
        .build()
        .unwrap()
        .spawn(async {

        });*/

    let node = Node::run(sk, pk);
    let mut reader = io::BufReader::new(io::stdin());
    loop {
        let mut buffer = String::new();
        reader.read_line(&mut buffer).await.unwrap();

        let mut words = buffer.split_whitespace();
        let command = words.next().unwrap();
        match command {
            "quit" => {
                node.shutdown();
                break;
            },
            "listen" => {
                let address = words.next().unwrap().parse().unwrap();
                node.send(Command::Listen {
                    local_host: address,
                })
                .ok()
                .unwrap();
            },
            "connect" => {
                let address = words.next().unwrap().parse().unwrap();
                let peer_pi = words.next().unwrap().parse().unwrap();
                node.send(Command::Connect {
                    remote_host: address,
                    remote_pi: peer_pi,
                })
                .ok()
                .unwrap();
            },
            "message" => {
                let peer_pi = words.next().unwrap().parse().unwrap();
                let message = words.next().unwrap().to_string();
                node.send(Command::Local {
                    command: LocalCommand::Message(message),
                    peer_pi: peer_pi,
                })
                .ok()
                .unwrap();
            },
            _ => println!("bad command"),
        }
    }
}
