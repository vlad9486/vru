use std::{env, fs};
use rand::Rng;
use structopt::StructOpt;
use rac::Array;
use vru_core::{run, OutgoingEvent, LocalOutgoingEvent, LinesStream, UnboundedReceiverStream};
use vru_transport::protocol::{PublicKey, PublicIdentity};
use tokio::{
    io::{self, AsyncBufReadExt},
    sync::mpsc,
    net::UnixListener,
    select,
    signal::ctrl_c,
};
use tokio_stream::StreamExt;

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
        let mut s = Array::default();
        s.clone_from_slice(kp.as_ref());
        s
    } else {
        let mut s = Array::default();
        rand::thread_rng().fill(s.as_mut());
        db.insert(b"key_seed", s.as_ref()).unwrap();
        s
    };
    let (sk, pk) = PublicKey::key_pair_seed(&seed);
    let pi = PublicIdentity::new(&pk);
    tracing::info!("identity: {}", pi);

    let control_path = format!("{}/.vru/{}.sock", env::var("HOME").unwrap(), opts.name);

    let (control_tx, control_rx) = mpsc::unbounded_channel();
    let control_rx = UnboundedReceiverStream::new(control_rx);
    let path = control_path.clone();
    tokio::spawn(async move {
        fs::remove_file(path.clone())
            .or_else(|e| {
                if let io::ErrorKind::NotFound = e.kind() {
                    Ok(())
                } else {
                    Err(e)
                }
            })
            .unwrap();
        let listener = UnixListener::bind(path).unwrap();
        loop {
            let (stream, _) = select! {
                pair = listener.accept() => pair.unwrap(),
                _ = ctrl_c() => break,
            };

            let lines = LinesStream::new(io::BufReader::new(stream).lines());
            let mut control = lines.filter_map(|line| line.ok()?.parse().ok());
            while let Some(c) = control.next().await {
                let _ = control_tx.send(c);
            }
        }
    });

    let etx = |e| match e {
        OutgoingEvent::Connection {
            peer_pi, address, ..
        } => {
            tracing::info!("connection {:?} {}", address, peer_pi);
        },
        OutgoingEvent::Event {
            peer_pi,
            event: LocalOutgoingEvent::ReceivedText(string),
        } => tracing::info!("received {} {:?}", peer_pi, string),
    };
    run(sk, pk, format!("0.0.0.0:{}", opts.port), control_rx, etx).await;
    fs::remove_file(control_path).unwrap()
}
