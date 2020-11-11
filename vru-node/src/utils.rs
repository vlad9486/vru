use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use rac::{Line, generic_array::GenericArray};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    stream::Stream,
};
use vru_transport::protocol::SimpleUnidirectional;

pub async fn read<T, L>(stream: &mut T) -> Result<L, io::Error>
where
    L: Line,
    T: Unpin + AsyncReadExt,
{
    let mut buffer = GenericArray::default();
    stream.read_exact(buffer.as_mut()).await?;
    tracing::debug!(read = buffer.len());
    Ok(L::clone_array(&buffer))
}

pub async fn write<T, L>(stream: &mut T, line: L) -> Result<(), io::Error>
where
    L: Line,
    T: Unpin + AsyncWriteExt,
{
    let buffer = line.clone_line();
    tracing::debug!(will_write = buffer.len());
    stream.write_all(buffer.as_ref()).await
}

pub async fn read_ciphered<T, L>(
    cipher: &mut SimpleUnidirectional,
    stream: &mut T,
) -> Result<L, io::Error>
where
    L: Line,
    T: Unpin + AsyncReadExt,
{
    let mut buffer = GenericArray::default();
    let mut tag = GenericArray::default();
    stream.read_exact(buffer.as_mut()).await?;
    stream.read_exact(tag.as_mut()).await?;
    cipher
        .decrypt(b"vru", buffer.as_mut(), &tag)
        .map_err(|()| io::Error::new(io::ErrorKind::Other, "MAC mismatch"))?;
    tracing::debug!(read = buffer.len() + tag.len());
    Ok(L::clone_array(&buffer))
}

pub async fn write_ciphered<T, L>(
    cipher: &mut SimpleUnidirectional,
    stream: &mut T,
    line: L,
) -> Result<(), io::Error>
where
    L: Line,
    T: Unpin + AsyncWriteExt,
{
    let mut buffer = line.clone_line();
    let tag = cipher.encrypt(b"vru", buffer.as_mut());
    tracing::debug!(will_write = buffer.len() + tag.len());
    stream.write_all(buffer.as_ref()).await?;
    stream.write_all(tag.as_ref()).await
}

pin_project_lite::pin_project! {
    #[must_use = "streams do nothing unless polled"]
    pub struct TcpListenerStream {
        #[pin]
        inner: TcpListener,
    }
}

impl TcpListenerStream {
    pub fn new(inner: TcpListener) -> Self {
        TcpListenerStream { inner: inner }
    }
}

impl Stream for TcpListenerStream {
    type Item = Result<(TcpStream, SocketAddr), io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().inner.poll_accept(cx).map(Some)
    }
}
