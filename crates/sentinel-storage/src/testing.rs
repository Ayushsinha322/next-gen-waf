//! Local stub servers for tests of the storage failure paths.
//!
//! The failures that matter — a server that accepts and never answers, one that
//! hangs up at once, a Valkey that answers the handshake and then stalls or
//! errors, a ClickHouse that commits an insert it answers too late — cannot be
//! produced with a real Valkey or ClickHouse, and the live tests that need one
//! are `#[ignore]`d in CI anyway. Compiled only for tests
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

/// How [`FakeClickHouse`] answers an `INSERT`. Everything else (`/ping`, DDL)
/// gets `200 Ok.`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertMode {
    /// Commit the rows and answer 200.
    Accept,
    /// Commit an INSERT of more than this many rows but never answer it: a
    /// server too slow for the client's deadline that still finishes the work,
    /// as ClickHouse does once the body has arrived.
    CommitSilentlyAbove(usize),
    /// Answer 500 (committing nothing) to the INSERT that would take the
    /// committed total past this many rows, and to every one after it.
    RejectAfter(usize),
}

/// A minimal ClickHouse HTTP endpoint that records the rows of each INSERT it
/// commits.
pub struct FakeClickHouse {
    pub addr: SocketAddr,
    committed: Arc<std::sync::Mutex<Vec<usize>>>,
}

impl FakeClickHouse {
    pub async fn start(mode: InsertMode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let committed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = Arc::clone(&committed);
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                tokio::spawn(serve_clickhouse(sock, mode, Arc::clone(&log)));
            }
        });
        Self { addr, committed }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Row count of each committed INSERT, in arrival order.
    pub fn inserts(&self) -> Vec<usize> {
        self.committed.lock().unwrap().clone()
    }

    /// Rows committed across every INSERT (duplicates included).
    pub fn committed_rows(&self) -> usize {
        self.inserts().iter().sum()
    }
}

const HTTP_OK_EMPTY: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";

/// One keep-alive HTTP/1.1 connection: read each request (headers, then a
/// `content-length` body), answer per `mode`.
async fn serve_clickhouse(
    mut sock: tokio::net::TcpStream,
    mode: InsertMode,
    committed: Arc<std::sync::Mutex<Vec<usize>>>,
) {
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let head_end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            match sock.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
        let len: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        while buf.len() < head_end + len {
            match sock.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        let body = String::from_utf8_lossy(&buf[head_end..head_end + len]).into_owned();
        buf.drain(..head_end + len);

        // `None`: committed, but never answered.
        let reply: Option<&[u8]> = if body.starts_with("INSERT") {
            let rows = body.lines().skip(1).filter(|l| !l.is_empty()).count();
            let mut log = committed.lock().unwrap();
            match mode {
                InsertMode::CommitSilentlyAbove(n) if rows > n => {
                    log.push(rows);
                    None
                }
                InsertMode::RejectAfter(total) if log.iter().sum::<usize>() + rows > total => {
                    Some(b"HTTP/1.1 500 Internal Server Error\r\ncontent-length: 4\r\n\r\nnope")
                }
                _ => {
                    log.push(rows);
                    Some(HTTP_OK_EMPTY)
                }
            }
        } else {
            Some(b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\nOk.\n")
        };
        let Some(reply) = reply else {
            // Hold the connection open, unanswered, until the client gives up
            // and closes it.
            let _ = sock.read(&mut chunk).await;
            return;
        };
        if sock.write_all(reply).await.is_err() {
            return;
        }
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
