#![allow(unused_variables, dead_code)]

use std::{collections::HashMap, io, thread, net::SocketAddr, sync::{Arc, atomic::AtomicBool, mpsc}};
use thiserror::Error;
use mio::{Poll, Waker, net::{TcpListener, TcpStream}};
use vru_session::{
    self as session,
    Command,
    Event,
    NodeDisconnected,
    handshake::{PublicKey, SecretKey, Identity},
};

pub struct NodeRef(mpsc::Receiver<Event<NodeError>>);

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("io error: {}", _0)]
    Io(io::Error),
}

impl session::NodeRef<NodeError> for NodeRef {
    fn recv(&self) -> Result<Event<NodeError>, NodeDisconnected> {
        self.0.recv().map_err(|mpsc::RecvError| NodeDisconnected)
    }

    fn try_recv(&self) -> Result<Option<Event<NodeError>>, NodeDisconnected> {
        self.0.try_recv()
            .map(Some)
            .or_else(|error| match error {
                mpsc::TryRecvError::Empty => Ok(None),
                mpsc::TryRecvError::Disconnected => Err(NodeDisconnected),
            })
    }
}

pub struct Node<P>
where
    P: session::ProcessorFactory,
{
    main_thread: thread::JoinHandle<()>,
    waker: Waker,
    sender: mpsc::Sender<Event<NodeError>>,
    incoming: mpsc::Receiver<(SocketAddr, Peer<P::Processor>)>,
    peers: HashMap<Identity, Peer<P::Processor>>,
    processor_factory: P,
}

impl<P> session::Node<P> for Node<P>
where
    P: session::ProcessorFactory + Clone + Send + 'static,
    P::Processor: Send,
{
    type Error = NodeError;
    type Ref = NodeRef;
    type Address = SocketAddr;

    fn spawn(
        sk: SecretKey,
        pk: PublicKey,
        address: Self::Address,
        processor_factory: P,
        running: Arc<AtomicBool>,
    ) -> Result<(Self, Self::Ref), Self::Error> {
        use mio::{Interest, Token};

        let (sender, rx) = mpsc::channel();
        let (peer_tx, peer_rx) = mpsc::channel();

        let poll = Poll::new().map_err(NodeError::Io)?;
        let waker = Waker::new(poll.registry(), Token(0)).map_err(NodeError::Io)?;

        let main_thread = {
            let mut listener = TcpListener::bind(address).map_err(NodeError::Io)?;

            poll.registry().register(&mut listener, Token(1), Interest::READABLE)
                .map_err(NodeError::Io)?;

            let state = NodeState::<P> {
                sk,
                pk,
                listener,
                poll,
                sender: sender.clone(),
                incoming: peer_tx,
                processor_factory: processor_factory.clone(),
            };
            thread::Builder::new()
                .name("node-main".to_string())
                .spawn(move || state.run(running))
                .expect("failed to spawn main thread")
        };

        Ok((
            Node {
                main_thread,
                waker,
                sender,
                incoming: peer_rx,
                peers: HashMap::new(),
                processor_factory,
            },
            NodeRef(rx),
        ))
    }

    fn command(&self, command: Command<Self::Address>) {
        match command {
            Command::Connect { peer_pi, address } => {
                let stream = TcpStream::connect(address).unwrap();
            },
            _ => (),
        }
    }

    fn join(self) {
        self.waker.wake().unwrap();
        self.main_thread.join().unwrap()
    }
}

struct NodeState<P>
where
    P: session::ProcessorFactory,
{
    sk: SecretKey,
    pk: PublicKey,
    listener: TcpListener,
    poll: Poll,
    sender: mpsc::Sender<Event<NodeError>>,
    incoming: mpsc::Sender<(SocketAddr, Peer<P::Processor>)>,
    processor_factory: P,
}

impl<P> NodeState<P>
where
    P: session::ProcessorFactory,
{
    fn run(mut self, running: Arc<AtomicBool>) {
        use std::{time::Duration, sync::atomic::Ordering};
        use mio::Events;

        let mut events = Events::with_capacity(2);

        while running.load(Ordering::Acquire) {
            loop {
                match self.poll.poll(&mut events, Some(Duration::from_secs(1))) {
                    Ok(events) => break events,
                    Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                        if !running.load(Ordering::Acquire) {
                            return;
                        }
                    },
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => return,
                    Err(error) => self.report(Event::Error(NodeError::Io(error))),
                }
            }

            for event in &events {
                match event.token().0 {
                    0 => {
                        log::info!("wake");
                        return;
                    },
                    1 => match self.listener.accept() {
                        Ok((stream, address)) => {
                            let processor = self.processor_factory.spawn_processor(None);
                            let peer = Peer::spawn(
                                self.sk.clone(),
                                self.pk.clone(),
                                stream,
                                processor,
                                running.clone(),
                            );
                            self.incoming.send((address, peer)).unwrap();
                        },
                        Err(error) => self.report(Event::Error(NodeError::Io(error))),
                    },
                    _ => unreachable!(),
                }
            }
        }
    }

    fn report(&self, event: Event<NodeError>) {
        match self.sender.send(event) {
            Ok(()) => (),
            Err(mpsc::SendError(event)) => log::warn!("failed to send event: {:?}", event),
        }
    }
}

struct Peer<P>
where
    P: session::Processor,
{
    worker_thread: thread::JoinHandle<()>,
    processor: P,
    waker: Waker,
    sender: mpsc::Sender<Vec<u8>>,
}

impl<P> Peer<P>
where
    P: session::Processor,
{
    fn spawn(
        sk: SecretKey,
        pk: PublicKey,
        stream: TcpStream,
        processor: P,
        running: Arc<AtomicBool>,
    ) -> Self {
        unimplemented!()
    }

    fn join(self) {
        self.worker_thread.join().unwrap()
    }
}
