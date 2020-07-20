use futures::{AsyncReadExt, AsyncWriteExt, io};
use core::fmt;
use super::session::Session;

#[cfg(feature = "std")]
use super::session::Choose;

/// Error that record the level on which it happens
#[derive(Debug)]
pub struct HierarchicError<Inner> {
    pub level: usize,
    pub inner: Inner,
}

impl<Inner> HierarchicError<Inner> {
    fn level(level: usize) -> impl FnOnce(Inner) -> Self {
        move |inner| HierarchicError { level, inner }
    }
}

impl<Inner> fmt::Display for HierarchicError<Inner>
where
    Inner: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "at level {}: {}", self.level, self.inner)
    }
}

/// Error of the communication
#[derive(Debug)]
pub enum ChannelError {
    /// Error while receive
    Receive(io::Error),
    /// Error while send
    Send(io::Error),
    /// Error decoding received bytes
    BadData(()),
}

impl fmt::Display for ChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            &ChannelError::Receive(ref e) => write!(f, "io error while receive: {}", e),
            &ChannelError::Send(ref e) => write!(f, "io error while send: {}", e),
            &ChannelError::BadData(()) => write!(f, "cannot decode received bytes"),
        }
    }
}

/// The communication channel
pub struct Channel<Input, Output>(pub Input, pub Output)
where
    Input: AsyncReadExt + Unpin,
    Output: AsyncWriteExt + Unpin;

impl<Input, Output> Channel<Input, Output>
where
    Input: AsyncReadExt + Unpin,
    Output: AsyncWriteExt + Unpin,
{
    /// Make one step through the session
    pub async fn step<S>(
        &mut self,
        session: S,
        level: usize,
    ) -> Result<S::Choose, HierarchicError<ChannelError>>
    where
        S: Session,
    {
        use rac::{LineValid, generic_array::GenericArray};
        use core::mem;

        let &mut Channel(ref mut input, ref mut output) = self;

        let value = {
            let mut buffer = GenericArray::default();
            if mem::size_of::<S::Receive>() != 0 {
                input
                    .read(&mut buffer)
                    .await
                    .map_err(ChannelError::Receive)
                    .map_err(HierarchicError::level(level))?;
            }
            S::Receive::try_clone_array(&buffer)
                .map_err(ChannelError::BadData)
                .map_err(HierarchicError::level(level))?
        };

        let (value, continuation) = session.step(value);
        if mem::size_of::<S::Send>() != 0 {
            output
                .write(value.clone_line().as_ref())
                .await
                .map_err(ChannelError::Send)
                .map_err(HierarchicError::level(level))?;
        }

        Ok(continuation)
    }

    #[cfg(feature = "std")]
    /// Execute the whole session, starting from some choice
    pub async fn execute<C>(&mut self, choose: C) -> Result<(), HierarchicError<ChannelError>>
    where
        C: Choose,
    {
        use std::{pin::Pin, future::Future};
        use either::Either;

        fn i<'a, C, Input, Output>(
            channel: &'a mut Channel<Input, Output>,
            choose: C,
            level: usize,
        ) -> Pin<Box<dyn Future<Output = Result<(), HierarchicError<ChannelError>>> + 'a>>
        where
            C: 'a + Choose,
            Input: AsyncReadExt + Unpin,
            Output: AsyncWriteExt + Unpin,
        {
            Box::pin(async move {
                match choose.choose() {
                    Either::Left(session) => {
                        if <C::Branch as Session>::END {
                            Ok(())
                        } else {
                            let new_choose = channel.step(session, level).await?;
                            i(channel, new_choose, level + 1).await
                        }
                    },
                    Either::Right(new_choose) => i(channel, new_choose, level + 1).await,
                }
            })
        }

        i::<C, Input, Output>(self, choose, 0).await
    }
}
