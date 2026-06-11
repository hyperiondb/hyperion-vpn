use std::future::{poll_fn, Future};
use std::task::Poll;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use yamux::{Config, Connection, Mode, Stream as YamuxStream};

use crate::{Error, Result};

pub type MuxStream = Compat<YamuxStream>;

const OPEN_BACKLOG: usize = 64;
const INBOUND_BACKLOG: usize = 128;

type OpenReply = oneshot::Sender<yamux::Result<YamuxStream>>;

pub fn config() -> Config {
    let mut cfg = Config::default();
    cfg.set_max_num_streams(512);
    cfg.set_split_send_size(16 * 1024);
    cfg
}

#[derive(Clone)]
pub struct MuxControl {
    open: mpsc::Sender<OpenReply>,
}

impl MuxControl {
    pub async fn open(&self) -> Result<MuxStream> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.open
            .send(reply_tx)
            .await
            .map_err(|_| Error::Protocol("mux driver stopped".into()))?;
        let stream = reply_rx
            .await
            .map_err(|_| Error::Protocol("mux driver stopped".into()))?
            .map_err(|e| Error::Protocol(format!("yamux open: {e}")))?;
        Ok(stream.compat())
    }
}

pub struct MuxAcceptor {
    inbound: mpsc::Receiver<YamuxStream>,
}

impl MuxAcceptor {
    pub async fn accept(&mut self) -> Option<MuxStream> {
        self.inbound.recv().await.map(|s| s.compat())
    }
}

pub fn client<T>(socket: T, cfg: Config) -> (MuxControl, impl Future<Output = Result<()>>)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let conn = Connection::new(socket.compat(), cfg, Mode::Client);
    let (open_tx, open_rx) = mpsc::channel(OPEN_BACKLOG);
    let (inbound_tx, _inbound_rx) = mpsc::channel(1);
    (
        MuxControl { open: open_tx },
        run(conn, Some(open_rx), inbound_tx),
    )
}

pub fn server<T>(socket: T, cfg: Config) -> (MuxAcceptor, impl Future<Output = Result<()>>)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let conn = Connection::new(socket.compat(), cfg, Mode::Server);
    let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_BACKLOG);
    (
        MuxAcceptor {
            inbound: inbound_rx,
        },
        run(conn, None, inbound_tx),
    )
}

async fn run<T>(
    mut conn: Connection<Compat<T>>,
    mut open_rx: Option<mpsc::Receiver<OpenReply>>,
    inbound_tx: mpsc::Sender<YamuxStream>,
) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut pending: Option<OpenReply> = None;
    poll_fn(|cx| loop {
        let mut progress = false;

        if let Some(reply) = pending.take() {
            match conn.poll_new_outbound(cx) {
                Poll::Ready(result) => {
                    let _ = reply.send(result);
                    progress = true;
                }
                Poll::Pending => pending = Some(reply),
            }
        }

        match conn.poll_next_inbound(cx) {
            Poll::Ready(Some(Ok(stream))) => {
                let _ = inbound_tx.try_send(stream);
                progress = true;
            }
            Poll::Ready(Some(Err(e))) => {
                return Poll::Ready(Err(Error::Protocol(format!("yamux: {e}"))))
            }
            Poll::Ready(None) => return Poll::Ready(Ok(())),
            Poll::Pending => {}
        }

        if pending.is_none() {
            if let Some(rx) = open_rx.as_mut() {
                match rx.poll_recv(cx) {
                    Poll::Ready(Some(reply)) => {
                        pending = Some(reply);
                        progress = true;
                    }
                    Poll::Ready(None) => open_rx = None,
                    Poll::Pending => {}
                }
            }
        }

        if !progress {
            return Poll::Pending;
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        read_connect_request, read_connect_response, write_connect_request,
        write_connect_response, ConnectRequest, ConnectResponse,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn pair() -> (MuxControl, MuxAcceptor) {
        let (a, b) = tokio::io::duplex(256 * 1024);
        let (control, client_driver) = client(a, config());
        let (acceptor, server_driver) = server(b, config());
        tokio::spawn(client_driver);
        tokio::spawn(server_driver);
        (control, acceptor)
    }

    #[tokio::test]
    async fn open_one_stream_request_response_echo() {
        let (control, mut acceptor) = pair();

        let server = tokio::spawn(async move {
            let mut s = acceptor.accept().await.unwrap();
            let req = read_connect_request(&mut s).await.unwrap();
            assert_eq!(req, ConnectRequest { port: 22 });
            write_connect_response(&mut s, ConnectResponse::Ok).await.unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
            s.flush().await.unwrap();
        });

        let mut s = control.open().await.unwrap();
        write_connect_request(&mut s, &ConnectRequest { port: 22 })
            .await
            .unwrap();
        let resp = read_connect_response(&mut s).await.unwrap();
        assert_eq!(resp, ConnectResponse::Ok);
        s.write_all(b"hello").await.unwrap();
        s.flush().await.unwrap();
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn many_concurrent_streams() {
        let (control, mut acceptor) = pair();

        tokio::spawn(async move {
            while let Some(mut s) = acceptor.accept().await {
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    s.read_to_end(&mut buf).await.unwrap();
                    s.write_all(&buf).await.unwrap();
                    s.shutdown().await.unwrap();
                });
            }
        });

        let mut handles = Vec::new();
        for i in 0..50u32 {
            let control = control.clone();
            handles.push(tokio::spawn(async move {
                let mut s = control.open().await.unwrap();
                let msg = format!("stream-{i}");
                s.write_all(msg.as_bytes()).await.unwrap();
                s.shutdown().await.unwrap();
                let mut buf = Vec::new();
                s.read_to_end(&mut buf).await.unwrap();
                assert_eq!(buf, msg.as_bytes());
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    }

    #[tokio::test]
    async fn half_close_then_response() {
        let (control, mut acceptor) = pair();

        let server = tokio::spawn(async move {
            let mut s = acceptor.accept().await.unwrap();
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.unwrap();
            assert_eq!(buf, b"half");
            s.write_all(b"closed").await.unwrap();
            s.shutdown().await.unwrap();
        });

        let mut s = control.open().await.unwrap();
        s.write_all(b"half").await.unwrap();
        s.shutdown().await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"closed");
        server.await.unwrap();
    }
}
