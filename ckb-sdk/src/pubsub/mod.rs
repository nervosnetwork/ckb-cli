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
    collections::{VecDeque, HashMap},
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
                    topic_list: vec![(res, name.to_string())].into_iter().collect(),
                    output: PhantomData::default(),
                    rpc_id: self.id,
                    pending_recv: VecDeque::default(),
                })
            }
            ckb_jsonrpc_types::response::Output::Failure(e) => {
                Err(io::Error::new(io::ErrorKind::InvalidData, e.error))
            }
        }
    }

    /// Subscription topics
    pub async fn subscribe_list<
        F: for<'de> serde::de::Deserialize<'de>,
        I: Iterator<Item = H>,
        H: AsRef<str>,
    >(
        mut self,
        name_list: I,
    ) -> io::Result<Handle<T, F>> {
        let mut topic_list = HashMap::default();
        let mut pending_recv = VecDeque::new();
        let mut inner = self.inner;

        for topic in name_list {
            let req_json = format!(
                r#"{{"id": {}, "jsonrpc": "2.0", "method": "subscribe", "params": ["{}"]}}"#,
                self.id,
                topic.as_ref()
            );
            self.id = self.id.wrapping_add(1);

            inner.send(req_json).await?;

            // loop util this subscribe success
            loop {
                let (resp, next_inner) = inner.into_future().await;
                inner = next_inner;
                let resp =
                    resp.ok_or_else::<io::Error, _>(|| io::ErrorKind::BrokenPipe.into())??;
                match serde_json::from_slice::<ckb_jsonrpc_types::response::Output>(&resp) {
                    Ok(output) => match output {
                        ckb_jsonrpc_types::response::Output::Success(success) => {
                            let res = serde_json::from_value::<String>(success.result).unwrap();
                            topic_list.insert(res, topic.as_ref().to_owned());
                            break;
                        }
                        ckb_jsonrpc_types::response::Output::Failure(e) => {
                            return Err(io::Error::new(io::ErrorKind::InvalidData, e.error))
                        }
                    },
                    // must be Notification message
                    Err(_) => pending_recv.push_back(resp),
                }
            }
        }

        Ok(Handle {
            inner,
            topic_list,
            output: PhantomData::default(),
            rpc_id: self.id,
            pending_recv,
        })
    }
}

/// General rpc subscription topic handle
pub struct Handle<T, F> {
    inner: Framed<T, StreamCodec>,
    topic_list: HashMap<String, String>,
    output: PhantomData<F>,
    rpc_id: usize,
    pending_recv: VecDeque<bytes::BytesMut>,
}

impl<T, F> Handle<T, F>
where
    T: tokio::io::AsyncWrite + tokio::io::AsyncRead + Unpin,
{
    /// Sub ids
    pub fn ids(&self) -> impl Iterator<Item=&String> {
        self.topic_list.keys()
    }

    /// Topic names
    pub fn topics(&self) -> impl Iterator<Item=&String> {
        self.topic_list.values()
    }

    /// Unsubscribe and return this Client
    pub async fn unsubscribe(mut self) -> io::Result<Client<T>> {
        let mut inner = self.inner;
        for id in self.topic_list.keys() {
            let req_json = format!(
                r#"{{"id": {}, "jsonrpc": "2.0", "method": "unsubscribe", "params": ["{}"]}}"#,
                self.rpc_id, id
            );
            self.rpc_id = self.rpc_id.wrapping_add(1);

            inner.send(req_json).await?;

            let output = loop {
                let (resp, next_inner) = inner.into_future().await;
                inner = next_inner;

                // Since the current subscription state, the return value may be a notification,
                // we need to ensure that the unsubscribed message returns before jumping out
                if let Ok(output) = serde_json::from_slice::<ckb_jsonrpc_types::response::Output>(
                    &resp.ok_or_else::<io::Error, _>(|| io::ErrorKind::BrokenPipe.into())??,
                ) {
                    break output;
                }
            };

            match output {
                ckb_jsonrpc_types::response::Output::Success(_) => (),
                ckb_jsonrpc_types::response::Output::Failure(e) => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, e.error))
                }
            }
        }
        Ok(Client {
            inner,
            id: self.rpc_id,
        })
    }
}

impl<T, F> Stream for Handle<T, F>
where
    F: for<'de> serde::de::Deserialize<'de> + Unpin,
    T: tokio::io::AsyncWrite + tokio::io::AsyncRead + Unpin,
{
    type Item = io::Result<(String, F)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let parse = |data: bytes::BytesMut, topic_list: &HashMap<String, String>| -> io::Result<(String, F)> {
            let output = serde_json::from_slice::<ckb_jsonrpc_types::request::Notification>(&data)
                .expect("must parse to notification");
            let message = output
                .params
                .parse::<Message>()
                .expect("must parse to message");
            serde_json::from_str::<F>(&message.result).map(|r| (topic_list.get(&message.subscription).cloned().unwrap(), r))
                .map_err(|_| io::ErrorKind::InvalidData.into())
        };

        if let Some(data) = self.pending_recv.pop_front() {
            return Poll::Ready(Some(parse(data, &self.topic_list)));
        }
        match self.inner.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(parse(frame, &self.topic_list))),
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
