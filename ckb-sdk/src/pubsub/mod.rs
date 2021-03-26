/// This module provides a general rpc subscription client,
/// you can use it with any connection method that implements `AsyncWrite + AsyncRead`.
/// The simplest TCP connection is as follows:
///
/// ```ignore
/// use ckb_jsonrpc_types::HeaderView;
/// use ckb_types::core::HeaderView as CoreHeaderView;
/// use tokio::net::{TcpStream, ToSocketAddrs};
///
/// pub async fn new_tcp_client(addr: impl ToSocketAddrs) -> io::Result<Client<TcpStream>> {
///     let tcp = TcpStream::connect(addr).await?;
///     Ok(Client::new(tcp))
/// }
///
/// fn main() {
///     let mut rt = tokio::runtime::Runtime::new().unwrap();
///     rt.block_on(async {
///         let c = new_tcp_client("127.0.0.1:18114").await.unwrap();
///         let mut h = c
///             .subscribe::<HeaderView>("new_tip_header")
///             .await
///             .unwrap();
///         while let Some(Ok(r)) = h.next().await {
///             let core: CoreHeaderView = r.into();
///             println!(
///                 "number: {}, difficulty: {}, epoch: {}, timestamp: {}",
///                 core.number(),
///                 core.difficulty(),
///                 core.epoch(),
///                 core.timestamp()
///             )
///         }
///     });   
/// }
/// ```
///
use std::{
    io,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{
    sink::SinkExt,
    stream::{Stream, StreamExt},
};
use serde::{Deserialize, Serialize};
use tokio_util::codec::Framed;

use stream_codec::StreamCodec;

mod stream_codec;

/// General rpc subscription client
pub struct Client<T> {
    inner: Framed<T, StreamCodec>,
    id: usize,
}

impl<T> Client<T>
where
    T: tokio::io::AsyncWrite + tokio::io::AsyncRead + Unpin,
{
    /// New a pubsub rpc client
    pub fn new(io: T) -> Client<T> {
        let inner = Framed::new(io, StreamCodec::stream_incoming());
        Client { inner, id: 0 }
    }

    /// Subscription a topic
    pub async fn subscribe<F: for<'de> serde::de::Deserialize<'de>>(
        mut self,
        name: &str,
    ) -> io::Result<Handle<T, F>> {
        // telnet localhost 18114
        // > {"id": 2, "jsonrpc": "2.0", "method": "subscribe", "params": ["new_tip_header"]}
        // < {"jsonrpc":"2.0","result":0,"id":2}
        // < {"jsonrpc":"2.0","method":"subscribe","params":{"result":"...block header json...",
        // "subscription":0}}
        // < {"jsonrpc":"2.0","method":"subscribe","params":{"result":"...block header json...",
        // "subscription":0}}
        // < ...
        // > {"id": 2, "jsonrpc": "2.0", "method": "unsubscribe", "params": [0]}
        // < {"jsonrpc":"2.0","result":true,"id":2}

        let req_json = format!(
            r#"{{"id": {}, "jsonrpc": "2.0", "method": "subscribe", "params": ["{}"]}}"#,
            self.id, name
        );
        self.id = self.id.wrapping_add(1);

        self.inner.send(req_json).await?;
        let (resp, inner) = self.inner.into_future().await;
        let output = serde_json::from_slice::<ckb_jsonrpc_types::response::Output>(
            &resp.ok_or_else::<io::Error, _>(|| io::ErrorKind::BrokenPipe.into())??,
        )?;

        match output {
            ckb_jsonrpc_types::response::Output::Success(success) => {
                let res = serde_json::from_value::<String>(success.result).unwrap();
                Ok(Handle {
                    inner,
                    topic: name.to_string(),
                    sub_id: res,
                    output: PhantomData::default(),
                    rpc_id: self.id,
                })
            }
            ckb_jsonrpc_types::response::Output::Failure(e) => {
                Err(io::Error::new(io::ErrorKind::InvalidData, e.error))
            }
        }
    }
}

/// General rpc subscription topic handle
pub struct Handle<T, F> {
    inner: Framed<T, StreamCodec>,
    topic: String,
    sub_id: String,
    output: PhantomData<F>,
    rpc_id: usize,
}

impl<T, F> Handle<T, F>
where
    T: tokio::io::AsyncWrite + tokio::io::AsyncRead + Unpin,
{
    /// Sub id
    pub fn id(&self) -> &str {
        &self.sub_id
    }

    /// Topic name
    pub fn topic(&self) -> &str {
        &self.topic
    }

    /// Unsubscribe and return this Client
    pub async fn unsubscribe(mut self) -> io::Result<Client<T>> {
        let req_json = format!(
            r#"{{"id": {}, "jsonrpc": "2.0", "method": "unsubscribe", "params": ["{}"]}}"#,
            self.rpc_id, self.sub_id
        );
        self.rpc_id = self.rpc_id.wrapping_add(1);

        self.inner.send(req_json).await?;

        let mut inner = self.inner;

        let (output, inner) = loop {
            let (resp, next_inner) = inner.into_future().await;

            // Since the current subscription state, the return value may be a notification,
            // we need to ensure that the unsubscribed message returns before jumping out
            if let Ok(output) = serde_json::from_slice::<ckb_jsonrpc_types::response::Output>(
                &resp.ok_or_else::<io::Error, _>(|| io::ErrorKind::BrokenPipe.into())??,
            ) {
                break (output, next_inner);
            } else {
                inner = next_inner;
            }
        };

        match output {
            ckb_jsonrpc_types::response::Output::Success(_) => Ok(Client {
                inner,
                id: self.rpc_id,
            }),
            ckb_jsonrpc_types::response::Output::Failure(e) => {
                Err(io::Error::new(io::ErrorKind::InvalidData, e.error))
            }
        }
    }
}

impl<T, F> Stream for Handle<T, F>
where
    F: for<'de> serde::de::Deserialize<'de> + Unpin,
    T: tokio::io::AsyncWrite + tokio::io::AsyncRead + Unpin,
{
    type Item = io::Result<F>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.inner.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                let output =
                    serde_json::from_slice::<ckb_jsonrpc_types::request::Notification>(&frame)
                        .expect("must parse to notification");
                let message = output
                    .params
                    .parse::<Message>()
                    .expect("must parse to message");

                Poll::Ready(Some(
                    serde_json::from_str::<F>(&message.result)
                        .map_err(|_| io::ErrorKind::InvalidData.into()),
                ))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
struct Message {
    result: String,
    subscription: String,
}
