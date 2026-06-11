use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectRequest {
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectResponse {
    Ok,
    Denied,
    Unreachable,
}

impl ConnectResponse {
    fn code(self) -> u8 {
        match self {
            ConnectResponse::Ok => 0,
            ConnectResponse::Denied => 1,
            ConnectResponse::Unreachable => 2,
        }
    }

    fn from_code(code: u8) -> Result<Self> {
        match code {
            0 => Ok(ConnectResponse::Ok),
            1 => Ok(ConnectResponse::Denied),
            2 => Ok(ConnectResponse::Unreachable),
            _ => Err(Error::Protocol("invalid connect response code".into())),
        }
    }
}

pub async fn write_connect_request<W>(w: &mut W, req: &ConnectRequest) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    w.write_all(&req.port.to_be_bytes()).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_connect_request<R>(r: &mut R) -> Result<ConnectRequest>
where
    R: AsyncRead + Unpin,
{
    let mut port = [0u8; 2];
    r.read_exact(&mut port).await?;
    Ok(ConnectRequest {
        port: u16::from_be_bytes(port),
    })
}

pub async fn write_connect_response<W>(w: &mut W, resp: ConnectResponse) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    w.write_all(&[resp.code()]).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_connect_response<R>(r: &mut R) -> Result<ConnectResponse>
where
    R: AsyncRead + Unpin,
{
    let mut code = [0u8; 1];
    r.read_exact(&mut code).await?;
    ConnectResponse::from_code(code[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_request_roundtrips() {
        let req = ConnectRequest { port: 22 };
        let mut buf = Vec::new();
        write_connect_request(&mut buf, &req).await.unwrap();
        let parsed = read_connect_request(&mut buf.as_slice()).await.unwrap();
        assert_eq!(parsed, req);
    }

    #[tokio::test]
    async fn read_connect_request_never_panics_or_hangs() {
        let mut buf = [0u8; 96];
        for _ in 0..2000 {
            getrandom::fill(&mut buf).unwrap();
            let len = buf[0] as usize % buf.len();
            let mut slice = &buf[..len];
            let _ = read_connect_request(&mut slice).await;
        }
    }
}
