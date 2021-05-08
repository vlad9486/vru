#![cfg(unix)]

mod listener_unix;
use self::listener_unix::CommandListener;

mod database;
use self::database::Database;

use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
struct Args {
    #[structopt(long)]
    path: PathBuf,
    #[structopt(long)]
    port: u16,
}

fn main() {
    use std::{
        thread,
        sync::{
            Arc,
            atomic::{Ordering, AtomicBool},
        },
    };
    use rand::Rng;
    use vru_transport::protocol::PublicIdentity;
    use vru_udp::Node;

    let Args { path, port } = Args::from_args();

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    tracing::info!("running, name: {:?}", path);

    let db_path = path.join("db");
    let db = match Database::open(&db_path) {
        Ok(v) => v,
        Err(error) => {
            tracing::error!(
                "fatal error: failed to open db at: {:?}, error: {}",
                db_path,
                error,
            );
            return;
        },
    };

    let (sk, pk) = match db.key_or_insert(|s| rand::thread_rng().fill(s.as_mut())) {
        Ok(v) => v,
        Err(error) => {
            tracing::error!("fatal error: failed to obtain key, error: {}", error);
            return;
        },
    };
    let pi = PublicIdentity::new(&pk);
    tracing::info!("identity: {}", pi);

    let running = Arc::new(AtomicBool::new(true));
    {
        let running = running.clone();
        match ctrlc::set_handler(move || running.store(false, Ordering::Release)) {
            Ok(()) => (),
            Err(error) => tracing::warn!("failed to listen ctrl+c, error: {}", error),
        }
    }

    let (node, node_ref) = match Node::spawn(sk, pk, port, running.clone()) {
        Ok(v) => v,
        Err(error) => {
            tracing::error!("fatal error: failed to create a node, error: {}", error);
            return;
        },
    };

    let event_stream = thread::spawn(move || {
        while let Ok(event) = node_ref.recv() {
            tracing::info!("{:?}", event);
        }
    });

    let path = path.join("ctrl.sock");
    match CommandListener::bind(path, running) {
        Ok(listener) => {
            for command in listener.into_iter() {
                match command {
                    Ok(command) => node.command(command),
                    Err(error) => log::warn!("failed to receive a command, error: {}", error),
                }
            }
        },
        Err(error) => log::error!("failed to listen commands, error: {}", error),
    }

    node.join();
    event_stream.join().unwrap();
}
