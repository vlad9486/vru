use std::{
    os::unix::net::UnixListener,
    path::Path,
    io, fs,
    sync::{
        Arc,
        atomic::{Ordering, AtomicBool},
    },
    marker::PhantomData,
    time::Duration,
};
use serde::de::DeserializeOwned;
use popol::{Sources, Events, interest};

pub struct CommandListener {
    running: Arc<AtomicBool>,
    listener: UnixListener,
    sources: Sources<()>,
    events: Events<()>,
}

pub struct CommandListenerIter<T>
where
    T: DeserializeOwned,
{
    inner: CommandListener,
    phantom_data: PhantomData<T>,
}

impl CommandListener {
    pub fn bind<P>(path: P, running: Arc<AtomicBool>) -> io::Result<Self>
    where
        P: AsRef<Path>,
    {
        let _ = fs::remove_file(&path);
        Ok(CommandListener {
            running,
            listener: UnixListener::bind(path)?,
            sources: Sources::with_capacity(1),
            events: Events::with_capacity(1),
        })
    }

    pub fn into_iter<T>(self) -> CommandListenerIter<T>
    where
        T: DeserializeOwned,
    {
        CommandListenerIter {
            inner: self,
            phantom_data: PhantomData,
        }
    }
}

impl<T> Iterator for CommandListenerIter<T>
where
    T: DeserializeOwned,
{
    type Item = bincode::Result<T>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner
            .sources
            .register((), &self.inner.listener, interest::READ);
        loop {
            match self
                .inner
                .sources
                .wait_timeout(&mut self.inner.events, Duration::from_secs(2))
            {
                Ok(()) => break,
                Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                    if !self.inner.running.load(Ordering::Acquire) {
                        return None;
                    }
                },
                Err(error) if error.kind() == io::ErrorKind::Interrupted => return None,
                Err(error) => {
                    return Some(Err(error.into()));
                },
            }
        }
        match self.inner.listener.accept() {
            Ok((stream, _)) => Some(bincode::deserialize_from(stream)),
            Err(error) => {
                if error.kind() == io::ErrorKind::Interrupted {
                    None
                } else {
                    Some(Err(error.into()))
                }
            },
        }
    }
}
