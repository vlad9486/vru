use std::{
    iter,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use rand::Rng;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use rac::Array;
use vru_transport::protocol::{PublicKey, SecretKey, PublicIdentity};
use crate::{run, Command, LocalCommand, OutgoingEvent, LocalOutgoingEvent, utils};

fn key() -> (PublicKey, SecretKey, PublicIdentity) {
    let mut seed = Array::default();
    rand::thread_rng().fill(seed.as_mut());

    let (sk, pk) = PublicKey::key_pair_seed(&seed);
    let pi = PublicIdentity::new(&pk);

    (pk, sk, pi)
}

#[tokio::test]
async fn b() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let (pk_a, sk_a, pi_a) = key();
    let (pk_b, sk_b, pi_b) = key();

    let sizes_b_to_a = [0, 640, 1259, 1260, 1261, 1400, 1259 + 1264, 1260 + 1264];

    let (tx, rx) = mpsc::unbounded_channel();
    let rx = utils::UnboundedReceiverStream::new(rx);

    let mut commands = sizes_b_to_a
        .iter()
        .map(|size| Command::Local {
            command: LocalCommand::SendText(iter::repeat('q').take(*size).collect()),
            peer_pi: pi_b.clone(),
        })
        .chain(iter::once(Command::Terminate))
        .collect::<Vec<_>>()
        .into_iter();
    let rx_a = rx.map(move |()| commands.next().unwrap());

    let tx_when_connect = tx.clone();
    let tx_a = move |event| match event {
        OutgoingEvent::Connection { .. } => tx_when_connect.send(()).unwrap(),
        OutgoingEvent::Event { .. } => (),
    };

    let (tx_when_terminate, rx_b) = mpsc::unbounded_channel();
    let rx_b = utils::UnboundedReceiverStream::new(rx_b);
    tx_when_terminate
        .send(Command::Connect {
            remote_address: "0.0.0.0:8224".parse().unwrap(),
            peer_pi: pi_a,
        })
        .ok()
        .unwrap();

    let e_counter = Arc::new(AtomicUsize::new(0));
    let tx_b = move |event| match event {
        OutgoingEvent::Connection { .. } => (),
        OutgoingEvent::Event {
            event: LocalOutgoingEvent::ReceivedText(string),
            ..
        } => {
            tx.send(()).unwrap();
            let size = sizes_b_to_a[e_counter.fetch_add(1, Ordering::SeqCst)];
            assert_eq!(size, string.len());
        },
    };

    tokio::spawn(async move {
        run(sk_a, pk_a, "0.0.0.0:8224", rx_a, tx_a).await;
        tx_when_terminate.send(Command::Terminate).ok().unwrap();
    });
    run(sk_b, pk_b, "0.0.0.0:8225", rx_b, tx_b).await;
}
