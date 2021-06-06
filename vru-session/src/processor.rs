use super::handshake::Identity;

pub trait ProcessorFactory {
    type Processor: Processor;

    fn spawn_processor(&mut self, peer_pi: Option<Identity>) -> Self::Processor;
}

pub trait Processor {
}

impl ProcessorFactory for () {
    type Processor = ();

    fn spawn_processor(&mut self, peer_pi: Option<Identity>) -> Self::Processor {
        let _ = peer_pi;
        ()
    }
}

impl Processor for () {}
