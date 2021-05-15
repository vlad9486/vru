use std::{
    cell::RefCell,
    collections::HashMap,
    io,
    net::{SocketAddr, UdpSocket},
    sync::{
        mpsc, Arc, Mutex,
        atomic::{Ordering, AtomicBool},
    },
    thread,
};
use thiserror::Error;
use super::{
    command::{Command, Event, Error, EventSender},
    local::{Peer, PeerHandle},
    session::{SecretKey, PublicKey, Identity, xx},
    linkage::{Datagram, LinkToken},
};

pub struct NodeRef(mpsc::Receiver<Event>);

#[derive(Debug, Error)]
#[error("node disconnected")]
pub struct NodeDisconnected;

impl NodeRef {
    pub fn recv(&self) -> Result<Event, NodeDisconnected> {
        self.0.recv().map_err(|mpsc::RecvError| NodeDisconnected)
    }

    pub fn try_recv(&self) -> Result<Option<Event>, NodeDisconnected> {
        match self.0.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Err(NodeDisconnected),
        }
    }
}

pub struct Node {
    sender: EventSender,
    pending_outgoing: Arc<Mutex<HashMap<SocketAddr, Identity>>>,
    pending_handles: Arc<Mutex<HashMap<Identity, PeerHandle>>>,
    handles: RefCell<HashMap<Identity, PeerHandle>>,
    main_thread: thread::JoinHandle<()>,
}

impl Node {
    pub fn spawn(
        sk: SecretKey,
        pk: PublicKey,
        port: u16,
        running: Arc<AtomicBool>,
    ) -> io::Result<(Self, NodeRef)> {
        let (sender, rx) = mpsc::channel();
        let sender = EventSender::new(sender);

        let pending_outgoing = Arc::new(Mutex::new(HashMap::new()));
        let pending_handles = Arc::new(Mutex::new(HashMap::new()));
        let handles = RefCell::new(HashMap::new());
        let main_thread = {
            let socket = UdpSocket::bind::<SocketAddr>(([0, 0, 0, 0], port).into())?;
            let listener = NodeState {
                sk,
                pk,
                socket,
                sender: sender.clone(),
                pending_outgoing: pending_outgoing.clone(),
                pending_handles: pending_handles.clone(),
                connections: HashMap::new(),
            };
            thread::Builder::new()
                .name("node-main".to_string())
                .spawn(move || listener.run(running))
                .expect("failed to spawn main thread")
        };

        Ok((
            Node {
                sender,
                pending_outgoing,
                pending_handles,
                handles,
                main_thread,
            },
            NodeRef(rx),
        ))
    }

    pub fn join(self) {
        self.main_thread.join().unwrap();
    }

    pub fn command(&self, command: Command) {
        match command {
            Command::Connect { address, peer_pi } => {
                let mut h = self.pending_outgoing.lock().unwrap();
                if h.contains_key(&address) {
                    self.sender
                        .report(Event::Error(Error::ConnectionFailed(address)));
                } else {
                    h.insert(address, peer_pi);
                }
            },
            Command::Local {
                destination,
                command,
            } => {
                if let Some(handle) = self.handles.borrow().get(&destination) {
                    handle.send(command);
                } else {
                    let mut h = self.pending_handles.lock().unwrap();
                    if let Some(handle) = h.remove(&destination) {
                        drop(h);
                        handle.send(command);
                        self.handles.borrow_mut().insert(destination, handle);
                    }
                }
            },
        }
    }
}

struct NodeState {
    sk: SecretKey,
    pk: PublicKey,
    socket: UdpSocket,
    sender: EventSender,
    pending_outgoing: Arc<Mutex<HashMap<SocketAddr, Identity>>>,
    pending_handles: Arc<Mutex<HashMap<Identity, PeerHandle>>>,
    connections: HashMap<LinkToken, Peer>,
}

impl NodeState {
    fn run(mut self, running: Arc<AtomicBool>) {
        use std::time::Duration;
        use popol::{Sources, Events, interest};

        let mut sources = Sources::with_capacity(1);
        sources.register((), &self.socket, interest::READ);
        let mut events = Events::with_capacity(1);

        while running.load(Ordering::Acquire) {
            loop {
                match sources.wait_timeout(&mut events, Duration::from_secs(2)) {
                    Ok(()) => break,
                    Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                        if !running.load(Ordering::Acquire) {
                            return;
                        }
                    },
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => return,
                    Err(error) => self.sender.report(Event::Error(Error::ReadSocket(error))),
                }
            }
            let mut datagram = Datagram::default();
            match self.socket.recv_from(datagram.as_mut()) {
                Ok((length, address)) => {
                    if length != Datagram::SIZE {
                        self.sender
                            .report(Event::Error(Error::FrameSize(address, length)));
                    } else {
                        self.process(address, datagram);
                    }
                },
                Err(error) => self.sender.report(Event::Error(Error::ReadSocket(error))),
            }
        }

        for (_, ctx) in self.connections {
            ctx.join();
        }
    }

    fn process(&mut self, address: SocketAddr, datagram: Datagram) {
        let link_token = datagram.link();
        if let Some(ctx) = self.connections.get(&link_token) {
            ctx.send(address, datagram);
        } else {
            let mut h = self.pending_outgoing.lock().unwrap();
            if let Some(peer_pi) = h.remove(&address) {
                drop(h);

                use rac::{Array, LineValid};
                let mut seed = Array::default();
                rand::Rng::fill(&mut rand::thread_rng(), seed.as_mut());
                let mut datagram = Datagram::default();
                let (state, message) = xx::out0(&seed, &peer_pi);
                datagram.as_mut()[..1120].clone_from_slice(&message.0.clone_line());
                rand::Rng::fill(&mut rand::thread_rng(), datagram.as_mut()[1120..].as_mut());
                if let Err(error) = self.socket.send_to(datagram.as_ref(), address) {
                    self.sender
                        .report(Event::Error(Error::WriteTo(address, error)));
                }

                let (sk, pk) = (self.sk.clone(), self.pk.clone());
                let sender = self.sender.clone();
                let (peer, peer_handle) = Peer::spawn(sk, pk, Some(state), sender);
                peer.send(address, datagram);
                // TODO:
                self.connections.insert(rand::random(), peer);
                let mut h = self.pending_handles.lock().unwrap();
                h.insert(peer_pi, peer_handle);
            } else {
                self.sender
                    .report(Event::Info(format!("incoming from: {}", address)));
            }
        }
    }
}
