use std::path::PathBuf;
use structopt::StructOpt;
use vru_node::{run, Command, LocalCommand};
use vru_transport::protocol::{PublicKey, PublicIdentity};
use tokio::io::{self, AsyncBufReadExt};
use tokio::stream::StreamExt;

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

    let control = io::BufReader::new(io::stdin())
        .lines()
        .take_while(|l| match &l {
            &Ok(ref s) => s != "quit",
            &Err(_) => true,
        })
        .filter_map(|line| {
            let line = line.ok()?;
            let mut words = line.split_whitespace();
            let command = words.next()?;
            match command {
                "listen" => {
                    let address = words.next()?.parse().ok()?;
                    Some(Command::Listen {
                        local_host: address,
                    })
                },
                "connect" => {
                    let address = words.next()?.parse().ok()?;
                    let peer_pi = words.next()?.parse().ok()?;
                    Some(Command::Connect {
                        remote_host: address,
                        remote_pi: peer_pi,
                    })
                },
                "message" => {
                    let peer_pi = words.next()?.parse().ok()?;
                    let message = words.next()?.to_string();
                    Some(Command::Local {
                        command: LocalCommand::Message(message),
                        peer_pi: peer_pi,
                    })
                },
                _ => {
                    println!("bad command");
                    None
                },
            }
        });
    tokio::spawn(async { run(sk, pk, control).await }).await.unwrap();
}
