use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use rac::{Line, generic_array::GenericArray};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, AsyncBufRead},
    net::{TcpListener, TcpStream},
    sync::mpsc::UnboundedReceiver,
    io::Lines,
};
use tokio_stream::Stream;
use vru_transport::protocol::TrivialUnidirectional as Cipher;

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

pub async fn write_ciphered<T, L>(
    cipher: &mut Cipher,
    stream: &mut T,
    line: L,
) -> Result<(), io::Error>
where
    L: Line,
    T: Unpin + AsyncWriteExt,
{
    write_all(cipher, stream, line.clone_line().as_mut()).await
}

pub async fn write_all<T>(
    cipher: &mut Cipher,
    stream: &mut T,
    buffer: &mut [u8],
) -> Result<(), io::Error>
where
    T: Unpin + AsyncWriteExt,
{
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

pin_project_lite::pin_project! {
    #[must_use = "streams do nothing unless polled"]
    pub struct UnboundedReceiverStream<T> {
        #[pin]
        inner: UnboundedReceiver<T>,
    }
}

impl<T> UnboundedReceiverStream<T> {
    pub fn new(inner: UnboundedReceiver<T>) -> Self {
        UnboundedReceiverStream { inner: inner }
    }
}

impl<T> Stream for UnboundedReceiverStream<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().inner.poll_recv(cx)
    }
}

pin_project_lite::pin_project! {
    #[must_use = "streams do nothing unless polled"]
    pub struct LinesStream<R> {
        #[pin]
        inner: Lines<R>,
    }
}

impl<R> LinesStream<R> {
    pub fn new(inner: Lines<R>) -> Self {
        LinesStream { inner: inner }
    }
}

impl<R> Stream for LinesStream<R>
where
    R: AsyncBufRead,
{
    type Item = Result<String, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project()
            .inner
            .poll_next_line(cx)
            .map(Result::transpose)
    }
}
