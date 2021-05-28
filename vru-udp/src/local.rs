use std::{net::SocketAddr, sync::mpsc, thread};
use vru_session::handshake::{PublicKey, SecretKey, xx};
use super::{
    command::{Event, LocalCommand, EventSender},
    linkage::Datagram,
};

enum PeerMessage {
    Network {
        address: SocketAddr,
        datagram: Datagram,
    },
    Command(LocalCommand),
}

pub struct Peer {
    worker_thread: thread::JoinHandle<()>,
    sender: mpsc::Sender<PeerMessage>,
}

impl Peer {
    pub fn send(&self, address: SocketAddr, datagram: Datagram) {
        self.sender
            .send(PeerMessage::Network { address, datagram })
            .unwrap()
    }

    pub fn join(self) {
        self.worker_thread.join().unwrap();
    }

    pub fn spawn(
        sk: SecretKey,
        pk: PublicKey,
        handshake_state: Option<xx::InitiatorsEphemeral>,
        event_sender: EventSender,
    ) -> (Self, PeerHandle) {
        let (sender, receiver) = mpsc::channel();

        let state = PeerState {
            sk,
            pk,
            handshake_state,
            receiver,
            event_sender,
        };
        let worker_thread = thread::Builder::new()
            .name("node-worker".to_string())
            .spawn(move || state.run())
            .expect("failed to spawn thread");

        (
            Peer {
                worker_thread,
                sender: sender.clone(),
            },
            PeerHandle { sender },
        )
    }
}

pub struct PeerHandle {
    sender: mpsc::Sender<PeerMessage>,
}

impl PeerHandle {
    pub fn send(&self, command: LocalCommand) {
        self.sender.send(PeerMessage::Command(command)).unwrap()
    }
}

struct PeerState {
    sk: SecretKey,
    pk: PublicKey,
    // TODO:
    handshake_state: Option<xx::InitiatorsEphemeral>,
    receiver: mpsc::Receiver<PeerMessage>,
    event_sender: EventSender,
}

impl PeerState {
    fn run(self) {
        // TODO:
        let _ = (&self.sk, &self.pk, &self.handshake_state);
        while let Ok(PeerMessage::Network { address, datagram }) = self.receiver.recv() {
            let _ = datagram;
            self.event_sender
                .report(Event::Info(format!("process connection with: {}", address)));
        }
    }
}
