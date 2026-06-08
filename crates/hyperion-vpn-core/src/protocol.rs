use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Error, Result};

pub const MAX_HOST_LEN: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    pub host: String,
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
    let host = req.host.as_bytes();
    if host.is_empty() || host.len() > MAX_HOST_LEN {
        return Err(Error::Protocol("host length out of range".into()));
    }
    let mut buf = Vec::with_capacity(1 + host.len() + 2);
    buf.push(host.len() as u8);
    buf.extend_from_slice(host);
    buf.extend_from_slice(&req.port.to_be_bytes());
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_connect_request<R>(r: &mut R) -> Result<ConnectRequest>
where
    R: AsyncRead + Unpin,
{
    let mut len = [0u8; 1];
    r.read_exact(&mut len).await?;
    let len = len[0] as usize;
    if len == 0 {
        return Err(Error::Protocol("empty host".into()));
    }
    let mut host = vec![0u8; len];
    r.read_exact(&mut host).await?;
    let mut port = [0u8; 2];
    r.read_exact(&mut port).await?;
    let host = String::from_utf8(host).map_err(|_| Error::Protocol("host not utf-8".into()))?;
    Ok(ConnectRequest {
        host,
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
