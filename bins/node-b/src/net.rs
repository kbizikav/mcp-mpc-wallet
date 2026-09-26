//! Where B listens: TCP (development) and vsock (inside a Nitro Enclave).
//!
//! An enclave cannot listen on TCP, so the parent instance relays TCP to vsock.
//! TLS terminates inside the enclave, so the parent only sees ciphertext.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

/// One of `127.0.0.1:7443`, `tcp:127.0.0.1:7443` or `vsock:7443`.
#[derive(Clone, Debug)]
pub enum Listen {
    Tcp(SocketAddr),
    Vsock(u32),
}

impl FromStr for Listen {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(port) = s.strip_prefix("vsock:") {
            return port
                .parse()
                .map(Listen::Vsock)
                .map_err(|e| format!("invalid vsock port: {e}"));
        }
        let addr = s.strip_prefix("tcp:").unwrap_or(s);
        addr.parse()
            .map(Listen::Tcp)
            .map_err(|e| format!("invalid address: {e}"))
    }
}

impl std::fmt::Display for Listen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Listen::Tcp(addr) => write!(f, "tcp:{addr}"),
            Listen::Vsock(port) => write!(f, "vsock:{port}"),
        }
    }
}

pub enum RawListener {
    Tcp(TcpListener),
    #[cfg(target_os = "linux")]
    Vsock(tokio_vsock::VsockListener),
}

impl RawListener {
    pub async fn bind(listen: &Listen) -> io::Result<Self> {
        match listen {
            Listen::Tcp(addr) => Ok(Self::Tcp(TcpListener::bind(addr).await?)),
            #[cfg(target_os = "linux")]
            Listen::Vsock(port) => Ok(Self::Vsock(tokio_vsock::VsockListener::bind(
                tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_ANY, *port),
            )?)),
            #[cfg(not(target_os = "linux"))]
            Listen::Vsock(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "vsock is only available on Linux",
            )),
        }
    }

    /// Accept a connection and return (stream, peer display name).
    pub async fn accept(&self) -> io::Result<(RawStream, String)> {
        match self {
            Self::Tcp(listener) => {
                let (stream, peer) = listener.accept().await?;
                Ok((RawStream::Tcp(stream), peer.to_string()))
            }
            #[cfg(target_os = "linux")]
            Self::Vsock(listener) => {
                let (stream, peer) = listener.accept().await?;
                Ok((RawStream::Vsock(stream), format!("vsock:{peer:?}")))
            }
        }
    }
}

pub enum RawStream {
    Tcp(TcpStream),
    #[cfg(target_os = "linux")]
    Vsock(tokio_vsock::VsockStream),
}

impl AsyncRead for RawStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(target_os = "linux")]
            Self::Vsock(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for RawStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(target_os = "linux")]
            Self::Vsock(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            #[cfg(target_os = "linux")]
            Self::Vsock(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(target_os = "linux")]
            Self::Vsock(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_listen_addresses() {
        assert!(matches!("127.0.0.1:7443".parse(), Ok(Listen::Tcp(_))));
        assert!(matches!("tcp:0.0.0.0:1".parse(), Ok(Listen::Tcp(_))));
        assert!(matches!("vsock:7443".parse(), Ok(Listen::Vsock(7443))));
        assert!("vsock:x".parse::<Listen>().is_err());
        assert!("nope".parse::<Listen>().is_err());
    }
}
