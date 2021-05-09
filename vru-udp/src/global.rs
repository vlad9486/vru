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
use vru_transport::protocol::{SecretKey, PublicKey, PublicIdentity, xk};
use rac::{Array, LineValid};
use super::{
    command::{Command, Event, Error, EventSender},
    local::{Peer, PeerHandle},
    DATAGRAM_SIZE,
};

pub struct NodeRef(mpsc::Receiver<Event>);

#[derive(Debug)]
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
    socket: UdpSocket,
    sender: EventSender,
    pending_outgoing: Arc<Mutex<HashMap<SocketAddr, (xk::StateEphemeral, PublicIdentity)>>>,
    pending_handles: Arc<Mutex<HashMap<PublicIdentity, PeerHandle>>>,
    handles: RefCell<HashMap<PublicIdentity, PeerHandle>>,
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

        let socket = UdpSocket::bind::<SocketAddr>(([0, 0, 0, 0], port).into())?;

        let pending_outgoing = Arc::new(Mutex::new(HashMap::new()));
        let pending_handles = Arc::new(Mutex::new(HashMap::new()));
        let handles = RefCell::new(HashMap::new());
        let main_thread = {
            let socket = socket.try_clone()?;
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
                socket,
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
                let mut seed = Array::default();
                rand::Rng::fill(&mut rand::thread_rng(), seed.as_mut());
                let mut datagram = [0; DATAGRAM_SIZE];
                let (state, message) = xk::State::new(&peer_pi).generate(&seed, &peer_pi).unwrap();
                datagram[..1120].clone_from_slice(&message.0.clone_line());
                rand::Rng::fill(&mut rand::thread_rng(), datagram[1120..].as_mut());

                let mut h = self.pending_outgoing.lock().unwrap();
                if h.contains_key(&address) {
                    self.sender.report(Event::Error(Error::ConnectionFailed(address)));
                } else {
                    h.insert(address, (state, peer_pi));
                    drop(h);
                    if let Err(error) = self.socket.send_to(&datagram, address) {
                        self.sender.report(Event::Error(Error::WriteTo(address, error)));
                    }
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

#[derive(Hash, Eq, PartialEq)]
struct LinkToken([u8; 16]);

struct NodeState {
    sk: SecretKey,
    pk: PublicKey,
    socket: UdpSocket,
    sender: EventSender,
    pending_outgoing: Arc<Mutex<HashMap<SocketAddr, (xk::StateEphemeral, PublicIdentity)>>>,
    pending_handles: Arc<Mutex<HashMap<PublicIdentity, PeerHandle>>>,
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
            let mut datagram = [0; DATAGRAM_SIZE];
            match self.socket.recv_from(datagram.as_mut()) {
                Ok((length, address)) => {
                    if length != DATAGRAM_SIZE {
                        self.sender.report(Event::Error(Error::FrameSize(address, length)));
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

    fn process(&mut self, address: SocketAddr, datagram: [u8; DATAGRAM_SIZE]) {
        let mut link_token = LinkToken([0; 16]);
        link_token.0.clone_from_slice(&datagram[..16]);
        if let Some(ctx) = self.connections.get(&link_token) {
            ctx.send(address, datagram);
        } else {
            let mut h = self.pending_outgoing.lock().unwrap();
            if let Some((state, peer_pi)) = h.remove(&address) {
                drop(h);
                let (sk, pk) = (self.sk.clone(), self.pk.clone());
                let sender = self.sender.clone();
                let (peer, peer_handle) = Peer::spawn(sk, pk, Some(state), sender);
                peer.send(address, datagram);
                let link_token = LinkToken([0; 16]); // TODO:
                self.connections.insert(link_token, peer);
                let mut h = self.pending_handles.lock().unwrap();
                h.insert(peer_pi, peer_handle);
            } else {
                self.sender.report(Event::Info(format!("incoming from: {}", address)));
            }
        }
    }
}
