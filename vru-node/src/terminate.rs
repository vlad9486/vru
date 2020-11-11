use std::{future::Future, mem};
use futures::{
    future::{FutureExt, Either, select, poll_fn},
    pin_mut,
};
use tokio::{sync::oneshot, task::JoinHandle, signal::ctrl_c};

pub struct Sender {
    inner: oneshot::Sender<()>,
}

pub struct Receiver {
    inner: oneshot::Receiver<()>,
    items: Vec<(Sender, JoinHandle<()>)>,
}

pub fn channel_ctrlc() -> Receiver {
    let (tx, rx) = channel();
    tokio::spawn(async move {
        ctrl_c().await.unwrap();
        tx.terminate()
    });

    rx
}

pub fn channel() -> (Sender, Receiver) {
    let (tx, rx) = oneshot::channel();
    (
        Sender { inner: tx },
        Receiver {
            inner: rx,
            items: Vec::new(),
        },
    )
}

impl Sender {
    pub fn terminate(self) {
        // safe to ignore
        let _ = self.inner.send(());
    }
}

impl Receiver {
    pub fn spawn<F, T>(&mut self, task: F)
    where
        F: FnOnce(Self) -> T,
        T: Future<Output = ()> + Send + 'static,
    {
        let (tx, rx) = channel();
        let handle = tokio::spawn(task(rx));
        self.items.push((tx, handle));
    }

    pub async fn should(&mut self) {
        let _ = poll_fn(|cx| self.inner.poll_unpin(cx)).await;
        let items = std::mem::replace(&mut self.items, Vec::new());
        for (sender, handle) in items {
            sender.terminate();
            handle.await.unwrap();
        }
    }

    pub async fn check<F, T>(&mut self, f: F) -> Option<T>
    where
        F: Future<Output = T>,
    {
        let inner = poll_fn(|cx| self.inner.poll_unpin(cx)).fuse();
        pin_mut!(inner);
        let f = f.fuse();
        pin_mut!(f);
        match select(inner, f).await {
            Either::Left((_, f)) => {
                let _ = f;
                tracing::info!("propagating termination signal to {}", self.items.len());
                let items = mem::replace(&mut self.items, Vec::new());
                for (sender, handle) in items {
                    sender.terminate();
                    handle.await.unwrap();
                }
                None
            },
            Either::Right((f, _)) => Some(f),
        }
    }
}
