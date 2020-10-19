use std::path::PathBuf;
use structopt::StructOpt;
use vru_node::run;
use vru_transport::protocol::{PublicKey, PublicIdentity};
use tokio::{
    io::{self, AsyncBufReadExt},
    stream::StreamExt,
};

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
        .filter_map(|line| line.ok()?.parse().ok());
    tokio::spawn(async { run(sk, pk, control).await }).await.unwrap();
}
