use std::{env, fs, convert::TryInto};
use rand::Rng;
use structopt::StructOpt;
use vru_node::{run, OutgoingEvent};
use vru_transport::protocol::{PublicKey, PublicIdentity};
use tokio::{
    io::{self, AsyncBufReadExt},
    sync::mpsc,
    net::UnixListener,
    stream::StreamExt,
    select,
    signal::ctrl_c,
};

#[derive(StructOpt)]
struct Opts {
    #[structopt(long, short)]
    name: String,
    #[structopt(long, short)]
    port: u16,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let opts = Opts::from_args();
    tracing::info!("running, name: {}", opts.name);

    let db_path = format!("{}/.vru/{}", env::var("HOME").unwrap(), opts.name);
    let db = sled::open(db_path).unwrap();

    let seed = if let Some(kp) = db.get(b"key_seed").unwrap() {
        kp.as_ref().try_into().unwrap()
    } else {
        let mut s = [0; 96];
        rand::thread_rng().fill(s.as_mut());
        db.insert(b"key_seed", s.as_ref()).unwrap();
        s
    };
    let (sk, pk) = PublicKey::key_pair_fixed(seed);
    let pi = PublicIdentity::new(&pk);
    tracing::info!("identity: {}", pi);

    let control_path = format!("{}/.vru/{}.sock", env::var("HOME").unwrap(), opts.name);

    let (control_tx, control_rx) = mpsc::channel(1);
    let path = control_path.clone();
    tokio::spawn(async move {
        let listener = UnixListener::bind(path).unwrap();
        loop {
            let (stream, _) = select! {
                pair = listener.accept() => pair.unwrap(),
                _ = ctrl_c() => break,
            };

            let mut control = io::BufReader::new(stream)
                .lines()
                .filter_map(|line| line.ok()?.parse().ok());
            while let Some(c) = control.next().await {
                let _ = control_tx.send(c).await;
            }
        }
    });

    run(sk, pk, format!("0.0.0.0:{}", opts.port), control_rx, |e| {
        match e {
            OutgoingEvent::Connection { peer_pi, address, .. } => {
                tracing::info!("connection {:?} {}", address, peer_pi);
            },
            _ => (),
        }
    })
    .await;
    fs::remove_file(control_path).unwrap();
}
