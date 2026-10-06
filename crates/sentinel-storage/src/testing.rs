//! Local stub servers for tests of the storage failure paths.
//!
//! The failures that matter — a server that accepts and never answers, one that
//! hangs up at once, a Valkey that answers the handshake and then stalls or
//! errors — cannot be produced with a real Valkey or ClickHouse, and the live
//! tests that need one are `#[ignore]`d in CI anyway. Compiled only for tests
//! (this crate's, and dependants' via the `test-support` feature).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Accepts connections and never sends a byte. Sockets are held open (not
/// dropped) so the client sees silence rather than EOF.
pub async fn black_hole() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock);
        }
    });
    addr
}

/// Accepts connections and closes each one immediately.
pub async fn hang_up() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            drop(sock);
        }
    });
    addr
}

/// How [`FakeValkey`] answers `EVALSHA`/`EVAL` (the rate-limit script).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EvalMode {
    /// `:1` — the request is within the limit.
    Allow = 0,
    /// `:0` — over the limit.
    Deny = 1,
    /// `-ERR` — a server-side failure.
    Error = 2,
    /// No reply at all; the connection stays open.
    Hang = 3,
}

/// A minimal RESP2 server: `+OK` to every handshake command, `+PONG` to PING,
/// and `EVALSHA`/`EVAL` answered per [`EvalMode`] (switchable at runtime).
pub struct FakeValkey {
    pub addr: SocketAddr,
    mode: Arc<AtomicU8>,
    evals: Arc<AtomicU64>,
}

impl FakeValkey {
    pub async fn start(mode: EvalMode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        Self::serve(listener, mode)
    }

    /// Serve on an already-bound listener (to bring a server up on a port a
    /// client is already retrying against).
    pub fn serve(listener: TcpListener, mode: EvalMode) -> Self {
        let addr = listener.local_addr().expect("addr");
        let mode = Arc::new(AtomicU8::new(mode as u8));
        let evals = Arc::new(AtomicU64::new(0));
        let (m, e) = (Arc::clone(&mode), Arc::clone(&evals));
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let (m, e) = (Arc::clone(&m), Arc::clone(&e));
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        let n = match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        buf.extend_from_slice(&chunk[..n]);
                        let mut out = Vec::new();
                        while let Some((args, used)) = parse_command(&buf) {
                            buf.drain(..used);
                            let name = args
                                .first()
                                .map(|a| String::from_utf8_lossy(a).to_ascii_uppercase())
                                .unwrap_or_default();
                            match name.as_str() {
                                "EVALSHA" | "EVAL" => {
                                    e.fetch_add(1, Ordering::SeqCst);
                                    match m.load(Ordering::SeqCst) {
                                        0 => out.extend_from_slice(b":1\r\n"),
                                        1 => out.extend_from_slice(b":0\r\n"),
                                        2 => out.extend_from_slice(b"-ERR fake failure\r\n"),
                                        _ => {}
                                    }
                                }
                                "PING" => out.extend_from_slice(b"+PONG\r\n"),
                                _ => out.extend_from_slice(b"+OK\r\n"),
                            }
                        }
                        if !out.is_empty() && sock.write_all(&out).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Self { addr, mode, evals }
    }

    pub fn url(&self) -> String {
        format!("redis://{}", self.addr)
    }

    pub fn set_mode(&self, mode: EvalMode) {
        self.mode.store(mode as u8, Ordering::SeqCst);
    }

    /// Rate-limit script invocations received so far.
    pub fn evals(&self) -> u64 {
        self.evals.load(Ordering::SeqCst)
    }
}

/// One RESP array-of-bulk-strings command from the front of `buf`, with the
/// bytes it occupied; `None` until a whole command has arrived.
fn parse_command(buf: &[u8]) -> Option<(Vec<Vec<u8>>, usize)> {
    fn line(buf: &[u8], from: usize) -> Option<(&[u8], usize)> {
        let rel = buf.get(from..)?.windows(2).position(|w| w == b"\r\n")?;
        Some((&buf[from..from + rel], from + rel + 2))
    }
    let (head, mut pos) = line(buf, 0)?;
    let n: usize = std::str::from_utf8(head.strip_prefix(b"*")?)
        .ok()?
        .parse()
        .ok()?;
    let mut args = Vec::with_capacity(n);
    for _ in 0..n {
        let (len_line, next) = line(buf, pos)?;
        let len: usize = std::str::from_utf8(len_line.strip_prefix(b"$")?)
            .ok()?
            .parse()
            .ok()?;
        let end = next + len;
        if buf.len() < end + 2 {
            return None;
        }
        args.push(buf[next..end].to_vec());
        pos = end + 2;
    }
    Some((args, pos))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_whole_commands_and_waits_for_partial_ones() {
        let cmd = b"*2\r\n$4\r\nPING\r\n$2\r\nhi\r\n";
        let (args, used) = parse_command(cmd).unwrap();
        assert_eq!(args, vec![b"PING".to_vec(), b"hi".to_vec()]);
        assert_eq!(used, cmd.len());
        assert!(parse_command(&cmd[..cmd.len() - 3]).is_none());
    }
}
