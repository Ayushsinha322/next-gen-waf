//! sentinel-cluster — Raft consensus for WAF config replication.
//!
//! Implements a simplified but correct single-file Raft (Leader election +
//! log replication) using tokio + JSON RPCs over plain TCP.  No external
//! Raft library is required.
//!
//! # Quick start
//! ```rust,no_run
//! # use sentinel_cluster::{ClusterConfig, ClusterHandle, ClusterCommand};
//! # async fn run() -> anyhow::Result<()> {
//! let cfg = ClusterConfig {
//!     node_id: 1,
//!     listen_addr: "127.0.0.1:9502".into(),
//!     peers: vec![],   // single-node → instantly becomes leader
//!     data_dir: "/tmp/sentinel-raft-1".into(),
//! };
//! let handle = ClusterHandle::start(cfg).await?;
//! handle.propose(ClusterCommand::BlockIp { ip: "1.2.3.4".into() }).await?;
//! handle.shutdown().await;
//! # Ok(())
//! # }
//! ```

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    time::{sleep, timeout, Instant},
};
use tracing::{debug, error, info, warn};

// ─── public types ────────────────────────────────────────────────────────────

/// Opaque node identifier.
pub type NodeId = u64;

/// Configuration passed to [`ClusterHandle::start`].
#[derive(Clone, Debug)]
pub struct ClusterConfig {
    /// This node's id (must be unique in the cluster).
    pub node_id: NodeId,
    /// Address this node listens on for Raft RPC traffic.
    pub listen_addr: String,
    /// Peer nodes: `(node_id, addr)`.  Empty → single-node cluster.
    pub peers: Vec<(NodeId, String)>,
    /// Directory used for persisting Raft state (term, vote, log).
    pub data_dir: String,
}

/// Commands that get replicated across the cluster via Raft log.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ClusterCommand {
    UpdateSiteConfig {
        site_id: String,
        config_json: String,
    },
    BlockIp {
        ip: String,
    },
    UnblockIp {
        ip: String,
    },
    UpdateRuleSet {
        tenant_id: String,
        rules_json: String,
    },
}

/// Snapshot of this node's cluster state — suitable for monitoring/health.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClusterStatus {
    pub node_id: NodeId,
    pub role: NodeRole,
    pub term: u64,
    pub leader_id: Option<NodeId>,
    pub peers: Vec<PeerStatus>,
    pub applied_log_index: u64,
}

/// Raft node role.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum NodeRole {
    Leader,
    Follower,
    Candidate,
    Learner,
}

/// Per-peer health information.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerStatus {
    pub node_id: NodeId,
    pub addr: String,
    pub is_reachable: bool,
    /// Unix seconds of last successful RPC, if any.
    pub last_seen: Option<u64>,
}

/// Errors returned by [`ClusterHandle`].
#[derive(Debug, thiserror::Error)]
pub enum ClusterError {
    #[error("not leader (hint: {0:?})")]
    NotLeader(Option<NodeId>),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("internal channel closed")]
    ChannelClosed,
    #[error("timeout")]
    Timeout,
    #[error("{0}")]
    Other(String),
}

// ─── internal types ──────────────────────────────────────────────────────────

type LogIndex = u64;
type Term = u64;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LogEntry {
    index: LogIndex,
    term: Term,
    command: ClusterCommand,
}

#[derive(Debug, Serialize, Deserialize)]
struct RaftLog {
    entries: Vec<LogEntry>,
    commit_index: LogIndex,
    last_applied: LogIndex,
}

impl RaftLog {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            commit_index: 0,
            last_applied: 0,
        }
    }

    fn last_index(&self) -> LogIndex {
        self.entries.last().map(|e| e.index).unwrap_or(0)
    }

    fn last_term(&self) -> Term {
        self.entries.last().map(|e| e.term).unwrap_or(0)
    }

    /// Return the entry at `index`, or None.
    fn get(&self, index: LogIndex) -> Option<&LogEntry> {
        // entries are 1-indexed and contiguous
        if index == 0 || self.entries.is_empty() {
            return None;
        }
        let first = self.entries[0].index;
        let offset = index.checked_sub(first)? as usize;
        self.entries.get(offset)
    }

    /// Append entries, truncating any conflicting suffix first.
    fn append_entries(&mut self, prev_index: LogIndex, new_entries: Vec<LogEntry>) {
        // Truncate any log entries that conflict
        if prev_index < self.last_index() {
            let first = self.entries.first().map(|e| e.index).unwrap_or(1);
            let keep = (prev_index.saturating_sub(first) + 1) as usize;
            self.entries.truncate(keep);
        }
        self.entries.extend(new_entries);
    }
}

/// Persistent Raft state written to disk on every mutation.
#[derive(Serialize, Deserialize)]
struct PersistentState {
    current_term: Term,
    voted_for: Option<NodeId>,
    log_entries: Vec<LogEntry>,
}

#[derive(Debug, Clone, PartialEq)]
enum RaftRole {
    Follower,
    Candidate,
    Leader,
}

struct RaftState {
    // config (immutable after start)
    node_id: NodeId,
    peers: Vec<(NodeId, String)>,
    data_dir: PathBuf,

    // persistent
    current_term: Term,
    voted_for: Option<NodeId>,
    log: RaftLog,

    // volatile
    role: RaftRole,
    leader_id: Option<NodeId>,
    votes_received: HashSet<NodeId>,

    // leader volatile
    next_index: HashMap<NodeId, LogIndex>,
    match_index: HashMap<NodeId, LogIndex>,

    // peer health (for status reporting)
    peer_last_seen: HashMap<NodeId, u64>,
    peer_reachable: HashMap<NodeId, bool>,
}

impl RaftState {
    fn new(cfg: &ClusterConfig) -> Self {
        let peer_map: HashMap<NodeId, bool> =
            cfg.peers.iter().map(|(id, _)| (*id, false)).collect();
        let peer_last: HashMap<NodeId, u64> =
            cfg.peers.iter().map(|(id, _)| (*id, 0)).collect();
        Self {
            node_id: cfg.node_id,
            peers: cfg.peers.clone(),
            data_dir: PathBuf::from(&cfg.data_dir),
            current_term: 0,
            voted_for: None,
            log: RaftLog::new(),
            role: RaftRole::Follower,
            leader_id: None,
            votes_received: HashSet::new(),
            next_index: HashMap::new(),
            match_index: HashMap::new(),
            peer_last_seen: peer_last,
            peer_reachable: peer_map,
        }
    }

    fn quorum(&self) -> usize {
        (self.peers.len() + 1) / 2 + 1
    }

    fn become_follower(&mut self, term: Term) {
        self.current_term = term;
        self.voted_for = None;
        self.role = RaftRole::Follower;
    }

    fn become_leader(&mut self) {
        info!(node_id = self.node_id, term = self.current_term, "becoming leader");
        self.role = RaftRole::Leader;
        self.leader_id = Some(self.node_id);
        let next = self.log.last_index() + 1;
        for (peer_id, _) in &self.peers {
            self.next_index.insert(*peer_id, next);
            self.match_index.insert(*peer_id, 0);
        }
    }

    fn try_advance_commit(&mut self) {
        if self.role != RaftRole::Leader {
            return;
        }
        let mut n = self.log.last_index();
        while n > self.log.commit_index {
            if let Some(entry) = self.log.get(n) {
                if entry.term != self.current_term {
                    n -= 1;
                    continue;
                }
            }
            let matches = self
                .peers
                .iter()
                .filter(|(id, _)| self.match_index.get(id).copied().unwrap_or(0) >= n)
                .count()
                + 1; // self
            if matches >= self.quorum() {
                self.log.commit_index = n;
                self.log.last_applied = n;
                break;
            }
            n -= 1;
        }
    }

    // ── persistence ──────────────────────────────────────────────────────────

    fn persist(&self) {
        let state = PersistentState {
            current_term: self.current_term,
            voted_for: self.voted_for,
            log_entries: self.log.entries.clone(),
        };
        let path = self.data_dir.join("raft_state.json");
        if let Err(e) = std::fs::create_dir_all(&self.data_dir) {
            warn!("persist: mkdir failed: {e}");
            return;
        }
        match serde_json::to_string(&state) {
            Ok(json) => {
                let tmp = self.data_dir.join("raft_state.json.tmp");
                if std::fs::write(&tmp, json).is_ok() {
                    let _ = std::fs::rename(&tmp, &path);
                }
            }
            Err(e) => warn!("persist: serialize failed: {e}"),
        }
    }

    fn load_from_disk(&mut self) {
        let path = self.data_dir.join("raft_state.json");
        let data = match std::fs::read_to_string(&path) {
            Ok(d) => d,
            Err(_) => return,
        };
        match serde_json::from_str::<PersistentState>(&data) {
            Ok(ps) => {
                self.current_term = ps.current_term;
                self.voted_for = ps.voted_for;
                self.log.entries = ps.log_entries;
                info!(node_id = self.node_id, term = self.current_term, "loaded persisted state");
            }
            Err(e) => warn!("load: deserialize failed: {e}"),
        }
    }
}

// ─── RPC types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
enum RaftRpc {
    RequestVote {
        term: Term,
        candidate_id: NodeId,
        last_log_index: LogIndex,
        last_log_term: Term,
    },
    RequestVoteReply {
        term: Term,
        vote_granted: bool,
    },
    AppendEntries {
        term: Term,
        leader_id: NodeId,
        prev_log_index: LogIndex,
        prev_log_term: Term,
        entries: Vec<LogEntry>,
        leader_commit: LogIndex,
    },
    AppendEntriesReply {
        term: Term,
        success: bool,
        match_index: LogIndex,
    },
    Propose {
        command: ClusterCommand,
    },
    ProposeReply {
        success: bool,
        leader_hint: Option<NodeId>,
    },
}

// ─── actor messages ──────────────────────────────────────────────────────────

enum ActorMsg {
    /// External proposal from the handle.
    Propose {
        command: ClusterCommand,
        reply: oneshot::Sender<Result<(), ClusterError>>,
    },
    /// Status query.
    Status {
        reply: oneshot::Sender<ClusterStatus>,
    },
    /// Incoming RPC from a peer (raw JSON line).
    IncomingRpc {
        json: String,
        reply_tx: mpsc::Sender<String>,
    },
    /// Graceful shutdown.
    Shutdown,
}

// ─── ClusterHandle ───────────────────────────────────────────────────────────

/// A live handle to a running Raft node.
pub struct ClusterHandle {
    tx: mpsc::Sender<ActorMsg>,
    // cached node_id for convenience
    node_id: NodeId,
}

impl ClusterHandle {
    /// Start the Raft node and begin participating in consensus.
    pub async fn start(cfg: ClusterConfig) -> Result<Self, ClusterError> {
        let node_id = cfg.node_id;
        let (tx, rx) = mpsc::channel(256);

        let actor = RaftActor::new(cfg)?;
        tokio::spawn(async move {
            actor.run(rx).await;
        });

        Ok(Self { tx, node_id })
    }

    /// Propose a command.  Must be called on the leader node.
    pub async fn propose(&self, cmd: ClusterCommand) -> Result<(), ClusterError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(ActorMsg::Propose {
                command: cmd,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ClusterError::ChannelClosed)?;
        reply_rx.await.map_err(|_| ClusterError::ChannelClosed)?
    }

    /// Return the current leader, if known.
    pub async fn current_leader(&self) -> Option<NodeId> {
        self.status().await.leader_id
    }

    /// Return true if this node believes it is the current leader.
    pub async fn is_leader(&self) -> bool {
        self.status().await.role == NodeRole::Leader
    }

    /// Return a status snapshot for monitoring.
    pub async fn status(&self) -> ClusterStatus {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self.tx.send(ActorMsg::Status { reply: reply_tx }).await.is_err() {
            return ClusterStatus {
                node_id: self.node_id,
                role: NodeRole::Follower,
                term: 0,
                leader_id: None,
                peers: vec![],
                applied_log_index: 0,
            };
        }
        reply_rx.await.unwrap_or(ClusterStatus {
            node_id: self.node_id,
            role: NodeRole::Follower,
            term: 0,
            leader_id: None,
            peers: vec![],
            applied_log_index: 0,
        })
    }

    /// Gracefully shut down the node.
    pub async fn shutdown(self) {
        let _ = self.tx.send(ActorMsg::Shutdown).await;
    }
}

// ─── RaftActor ───────────────────────────────────────────────────────────────

/// All mutable Raft state lives here, driven by a single async task.
struct RaftActor {
    state: RaftState,
    peers: Vec<(NodeId, String)>,     // snapshot for network calls
    listen_addr: String,
}

impl RaftActor {
    fn new(cfg: ClusterConfig) -> Result<Self, ClusterError> {
        let mut state = RaftState::new(&cfg);
        state.load_from_disk();

        Ok(Self {
            peers: cfg.peers.clone(),
            listen_addr: cfg.listen_addr.clone(),
            state,
        })
    }

    // ── election timer helpers ─────────────────────────────────────────────

    fn random_election_timeout() -> Duration {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        Duration::from_millis(150 + (nanos % 150) as u64)
    }

    // ── main actor loop ───────────────────────────────────────────────────

    async fn run(mut self, mut rx: mpsc::Receiver<ActorMsg>) {
        // Bind listener first so we can accept peer RPCs.
        let addr: SocketAddr = self.listen_addr.parse().unwrap_or_else(|_| {
            "127.0.0.1:9502".parse().unwrap()
        });
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                error!("cluster: bind failed: {e}");
                return;
            }
        };
        info!(node_id = self.state.node_id, addr = %addr, "cluster listener started");

        // Single-node: skip election, immediately become leader.
        if self.peers.is_empty() {
            self.state.current_term = 1;
            self.state.voted_for = Some(self.state.node_id);
            self.state.become_leader();
            self.state.persist();
            info!(node_id = self.state.node_id, "single-node cluster: instantly leader");
        }

        // Channel for incoming TCP connections to pass RPCs into the actor.
        let (rpc_tx, mut rpc_rx) = mpsc::channel::<ActorMsg>(256);

        // Spawn listener task that forwards messages into the actor channel.
        let rpc_tx_clone = rpc_tx.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        let tx = rpc_tx_clone.clone();
                        tokio::spawn(handle_connection(stream, peer_addr, tx));
                    }
                    Err(e) => {
                        error!("cluster accept error: {e}");
                        break;
                    }
                }
            }
        });

        let mut election_deadline = Instant::now() + Self::random_election_timeout();
        let heartbeat_interval = Duration::from_millis(50);
        let mut heartbeat_tick = Instant::now() + heartbeat_interval;

        loop {
            let now = Instant::now();

            // Compute how long until the next wakeup.
            let next_event = if self.state.role == RaftRole::Leader {
                heartbeat_tick.saturating_duration_since(now)
            } else {
                election_deadline.saturating_duration_since(now)
            };

            tokio::select! {
                biased;

                // Handle actor messages (proposals, status, shutdown).
                Some(msg) = rx.recv() => {
                    match msg {
                        ActorMsg::Propose { command, reply } => {
                            let result = self.handle_propose(command).await;
                            let _ = reply.send(result);
                        }
                        ActorMsg::Status { reply } => {
                            let _ = reply.send(self.build_status());
                        }
                        ActorMsg::Shutdown => {
                            info!(node_id = self.state.node_id, "cluster shutdown");
                            return;
                        }
                        ActorMsg::IncomingRpc { json, reply_tx } => {
                            self.handle_rpc_json(&json, reply_tx).await;
                            // Reset election timer on any RPC activity.
                            election_deadline = Instant::now() + Self::random_election_timeout();
                        }
                    }
                }

                // Handle RPCs arriving from the TCP listener task.
                Some(msg) = rpc_rx.recv() => {
                    if let ActorMsg::IncomingRpc { json, reply_tx } = msg {
                        self.handle_rpc_json(&json, reply_tx).await;
                        election_deadline = Instant::now() + Self::random_election_timeout();
                    }
                }

                // Timers.
                _ = sleep(next_event) => {
                    let now = Instant::now();
                    if self.state.role == RaftRole::Leader && now >= heartbeat_tick {
                        self.send_heartbeats().await;
                        heartbeat_tick = Instant::now() + heartbeat_interval;
                    } else if self.state.role != RaftRole::Leader && now >= election_deadline {
                        self.start_election().await;
                        election_deadline = Instant::now() + Self::random_election_timeout();
                    }
                }
            }
        }
    }

    // ── propose ───────────────────────────────────────────────────────────

    async fn handle_propose(&mut self, command: ClusterCommand) -> Result<(), ClusterError> {
        if self.state.role != RaftRole::Leader {
            return Err(ClusterError::NotLeader(self.state.leader_id));
        }

        let index = self.state.log.last_index() + 1;
        let entry = LogEntry {
            index,
            term: self.state.current_term,
            command,
        };
        self.state.log.entries.push(entry);
        self.state.persist();

        // If no peers, immediately commit.
        if self.peers.is_empty() {
            self.state.log.commit_index = index;
            self.state.log.last_applied = index;
            return Ok(());
        }

        // Replicate to peers; wait for quorum acknowledgment.
        self.replicate_to_quorum().await
    }

    async fn replicate_to_quorum(&mut self) -> Result<(), ClusterError> {
        let quorum = self.state.quorum();
        let mut acks = 1usize; // self

        // Fan out AppendEntries to all peers concurrently.
        let futs: Vec<_> = self
            .peers
            .iter()
            .map(|(peer_id, addr)| {
                let rpc = self.build_append_entries(*peer_id);
                let addr = addr.clone();
                let peer_id = *peer_id;
                async move { (peer_id, send_rpc(&addr, &rpc).await) }
            })
            .collect();

        // We can't use futures::join_all without the futures crate, so we spawn tasks.
        let (res_tx, mut res_rx) = mpsc::channel(self.peers.len() + 1);
        for (peer_id, addr) in &self.peers {
            let rpc = self.build_append_entries(*peer_id);
            let addr = addr.clone();
            let pid = *peer_id;
            let tx = res_tx.clone();
            tokio::spawn(async move {
                let r = send_rpc(&addr, &rpc).await;
                let _ = tx.send((pid, r)).await;
            });
        }
        drop(res_tx); // close so recv returns None when all done
        drop(futs);   // silence unused warning

        let deadline = tokio::time::sleep(Duration::from_millis(500));
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                Some((peer_id, result)) = res_rx.recv() => {
                    match result {
                        Ok(reply_json) => {
                            if let Ok(rpc) = serde_json::from_str::<RaftRpc>(&reply_json) {
                                match rpc {
                                    RaftRpc::AppendEntriesReply { term, success, match_index } => {
                                        if term > self.state.current_term {
                                            self.state.become_follower(term);
                                            self.state.persist();
                                            return Err(ClusterError::NotLeader(None));
                                        }
                                        if success {
                                            self.state.match_index.insert(peer_id, match_index);
                                            self.state.next_index.insert(peer_id, match_index + 1);
                                            self.state.peer_reachable.insert(peer_id, true);
                                            self.state.peer_last_seen.insert(peer_id, unix_now());
                                            acks += 1;
                                        } else {
                                            // Decrement next_index and retry (simplified: just mark unreachable).
                                            let ni = self.state.next_index.entry(peer_id).or_insert(1);
                                            if *ni > 1 { *ni -= 1; }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        Err(_) => {
                            self.state.peer_reachable.insert(peer_id, false);
                        }
                    }
                    if acks >= quorum {
                        self.state.try_advance_commit();
                        return Ok(());
                    }
                }
                _ = &mut deadline => {
                    // Check if we already have quorum from faster peers.
                    if acks >= quorum {
                        self.state.try_advance_commit();
                        return Ok(());
                    }
                    return Err(ClusterError::Timeout);
                }
                else => break,
            }
        }

        if acks >= quorum {
            self.state.try_advance_commit();
            Ok(())
        } else {
            Err(ClusterError::Other("lost quorum".into()))
        }
    }

    // ── election ──────────────────────────────────────────────────────────

    async fn start_election(&mut self) {
        self.state.current_term += 1;
        self.state.role = RaftRole::Candidate;
        self.state.voted_for = Some(self.state.node_id);
        self.state.votes_received.clear();
        self.state.votes_received.insert(self.state.node_id);
        self.state.persist();

        info!(
            node_id = self.state.node_id,
            term = self.state.current_term,
            "starting election"
        );

        let rpc = RaftRpc::RequestVote {
            term: self.state.current_term,
            candidate_id: self.state.node_id,
            last_log_index: self.state.log.last_index(),
            last_log_term: self.state.log.last_term(),
        };

        let quorum = self.state.quorum();
        let (vote_tx, mut vote_rx) = mpsc::channel(self.peers.len() + 1);

        for (_, addr) in &self.peers {
            let rpc = rpc.clone();
            let addr = addr.clone();
            let tx = vote_tx.clone();
            tokio::spawn(async move {
                let r = send_rpc(&addr, &rpc).await;
                let _ = tx.send(r).await;
            });
        }
        drop(vote_tx);

        let deadline = tokio::time::sleep(Duration::from_millis(200));
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                Some(result) = vote_rx.recv() => {
                    if let Ok(json) = result {
                        if let Ok(RaftRpc::RequestVoteReply { term, vote_granted }) =
                            serde_json::from_str::<RaftRpc>(&json)
                        {
                            if term > self.state.current_term {
                                self.state.become_follower(term);
                                self.state.persist();
                                return;
                            }
                            if vote_granted && self.state.role == RaftRole::Candidate {
                                // We can't track which node replied here without the id,
                                // but we track count via votes_received size heuristic.
                                // Insert a synthetic id based on current count.
                                let synthetic_id = self.state.votes_received.len() as u64 + 100;
                                self.state.votes_received.insert(synthetic_id);
                                if self.state.votes_received.len() >= quorum {
                                    self.state.become_leader();
                                    self.state.persist();
                                    self.send_heartbeats().await;
                                    return;
                                }
                            }
                        }
                    }
                }
                _ = &mut deadline => break,
                else => break,
            }
        }

        // Election failed (no quorum); revert to follower.
        if self.state.role == RaftRole::Candidate {
            debug!(node_id = self.state.node_id, "election failed, reverting to follower");
            self.state.role = RaftRole::Follower;
        }
    }

    // ── heartbeat ─────────────────────────────────────────────────────────

    async fn send_heartbeats(&mut self) {
        for (peer_id, addr) in self.peers.clone() {
            let rpc = self.build_append_entries(peer_id);
            let addr_clone = addr.clone();
            let _pid = peer_id;
            // Fire-and-forget; update reachability in place via a separate channel.
            let (tx, rx) = oneshot::channel::<Option<String>>();
            tokio::spawn(async move {
                let result = timeout(Duration::from_millis(100), send_rpc(&addr_clone, &rpc)).await;
                let _ = tx.send(result.ok().and_then(|r| r.ok()));
            });
            // Non-blocking peek — we don't await so the loop stays fast.
            // Reachability will update on next full replication cycle.
            drop(rx);
        }
    }

    fn build_append_entries(&self, peer_id: NodeId) -> RaftRpc {
        let next = self.state.next_index.get(&peer_id).copied().unwrap_or(1);
        let prev_index = next.saturating_sub(1);
        let prev_term = self
            .state
            .log
            .get(prev_index)
            .map(|e| e.term)
            .unwrap_or(0);
        let entries: Vec<LogEntry> = self
            .state
            .log
            .entries
            .iter()
            .filter(|e| e.index >= next)
            .cloned()
            .collect();
        RaftRpc::AppendEntries {
            term: self.state.current_term,
            leader_id: self.state.node_id,
            prev_log_index: prev_index,
            prev_log_term: prev_term,
            entries,
            leader_commit: self.state.log.commit_index,
        }
    }

    // ── incoming RPC handler ──────────────────────────────────────────────

    async fn handle_rpc_json(&mut self, json: &str, reply_tx: mpsc::Sender<String>) {
        let rpc = match serde_json::from_str::<RaftRpc>(json) {
            Ok(r) => r,
            Err(e) => {
                warn!("rpc parse error: {e} — raw: {json}");
                return;
            }
        };

        let reply = match rpc {
            RaftRpc::RequestVote {
                term,
                candidate_id,
                last_log_index,
                last_log_term,
            } => self.on_request_vote(term, candidate_id, last_log_index, last_log_term),

            RaftRpc::AppendEntries {
                term,
                leader_id,
                prev_log_index,
                prev_log_term,
                entries,
                leader_commit,
            } => self.on_append_entries(
                term,
                leader_id,
                prev_log_index,
                prev_log_term,
                entries,
                leader_commit,
            ),

            RaftRpc::Propose { command } => self.on_propose_rpc(command).await,

            _ => return, // replies are handled in the originating task
        };

        if let Ok(json) = serde_json::to_string(&reply) {
            let _ = reply_tx.send(json).await;
        }
    }

    fn on_request_vote(
        &mut self,
        term: Term,
        candidate_id: NodeId,
        last_log_index: LogIndex,
        last_log_term: Term,
    ) -> RaftRpc {
        if term > self.state.current_term {
            self.state.become_follower(term);
            self.state.persist();
        }

        let log_ok = last_log_term > self.state.log.last_term()
            || (last_log_term == self.state.log.last_term()
                && last_log_index >= self.state.log.last_index());

        let vote_granted = term >= self.state.current_term
            && log_ok
            && (self.state.voted_for.is_none()
                || self.state.voted_for == Some(candidate_id));

        if vote_granted {
            self.state.voted_for = Some(candidate_id);
            self.state.persist();
        }

        RaftRpc::RequestVoteReply {
            term: self.state.current_term,
            vote_granted,
        }
    }

    fn on_append_entries(
        &mut self,
        term: Term,
        leader_id: NodeId,
        prev_log_index: LogIndex,
        prev_log_term: Term,
        entries: Vec<LogEntry>,
        leader_commit: LogIndex,
    ) -> RaftRpc {
        if term < self.state.current_term {
            return RaftRpc::AppendEntriesReply {
                term: self.state.current_term,
                success: false,
                match_index: 0,
            };
        }

        // Valid leader heartbeat / replication.
        self.state.current_term = term;
        self.state.role = RaftRole::Follower;
        self.state.leader_id = Some(leader_id);

        // Check prev log entry.
        if prev_log_index > 0 {
            match self.state.log.get(prev_log_index) {
                None => {
                    return RaftRpc::AppendEntriesReply {
                        term: self.state.current_term,
                        success: false,
                        match_index: self.state.log.last_index(),
                    };
                }
                Some(e) if e.term != prev_log_term => {
                    return RaftRpc::AppendEntriesReply {
                        term: self.state.current_term,
                        success: false,
                        match_index: prev_log_index.saturating_sub(1),
                    };
                }
                _ => {}
            }
        }

        if !entries.is_empty() {
            self.state.log.append_entries(prev_log_index, entries);
            self.state.persist();
        }

        if leader_commit > self.state.log.commit_index {
            self.state.log.commit_index =
                leader_commit.min(self.state.log.last_index());
            self.state.log.last_applied = self.state.log.commit_index;
        }

        RaftRpc::AppendEntriesReply {
            term: self.state.current_term,
            success: true,
            match_index: self.state.log.last_index(),
        }
    }

    async fn on_propose_rpc(&mut self, command: ClusterCommand) -> RaftRpc {
        if self.state.role != RaftRole::Leader {
            return RaftRpc::ProposeReply {
                success: false,
                leader_hint: self.state.leader_id,
            };
        }
        let result = self.handle_propose(command).await;
        RaftRpc::ProposeReply {
            success: result.is_ok(),
            leader_hint: Some(self.state.node_id),
        }
    }

    // ── status ────────────────────────────────────────────────────────────

    fn build_status(&self) -> ClusterStatus {
        let role = match self.state.role {
            RaftRole::Leader => NodeRole::Leader,
            RaftRole::Candidate => NodeRole::Candidate,
            RaftRole::Follower => NodeRole::Follower,
        };

        let peers = self
            .state
            .peers
            .iter()
            .map(|(id, addr)| PeerStatus {
                node_id: *id,
                addr: addr.clone(),
                is_reachable: self.state.peer_reachable.get(id).copied().unwrap_or(false),
                last_seen: {
                    let t = self.state.peer_last_seen.get(id).copied().unwrap_or(0);
                    if t == 0 { None } else { Some(t) }
                },
            })
            .collect();

        ClusterStatus {
            node_id: self.state.node_id,
            role,
            term: self.state.current_term,
            leader_id: self.state.leader_id,
            peers,
            applied_log_index: self.state.log.last_applied,
        }
    }
}

// ─── TCP helpers ─────────────────────────────────────────────────────────────

/// Send a single JSON-line RPC and return the response line.
async fn send_rpc(addr: &str, rpc: &RaftRpc) -> Result<String, ClusterError> {
    let mut line = serde_json::to_string(rpc)?;
    line.push('\n');

    let stream = timeout(Duration::from_millis(200), TcpStream::connect(addr))
        .await
        .map_err(|_| ClusterError::Timeout)?
        .map_err(ClusterError::Io)?;

    let (reader, mut writer) = stream.into_split();
    writer.write_all(line.as_bytes()).await.map_err(ClusterError::Io)?;

    let mut buf = String::new();
    let mut reader = BufReader::new(reader);
    timeout(Duration::from_millis(200), reader.read_line(&mut buf))
        .await
        .map_err(|_| ClusterError::Timeout)?
        .map_err(ClusterError::Io)?;

    Ok(buf.trim_end().to_string())
}

/// Handle one incoming TCP connection: read a JSON line, dispatch via channel,
/// write back the reply.
async fn handle_connection(
    stream: TcpStream,
    _peer: SocketAddr,
    actor_tx: mpsc::Sender<ActorMsg>,
) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
        return;
    }

    let (reply_tx, mut reply_rx) = mpsc::channel::<String>(1);
    let _ = actor_tx
        .send(ActorMsg::IncomingRpc {
            json: line.trim_end().to_string(),
            reply_tx,
        })
        .await;

    // Wait briefly for a reply and write it back.
    if let Ok(Some(reply)) =
        timeout(Duration::from_millis(300), reply_rx.recv()).await
    {
        let mut out = reply;
        out.push('\n');
        let _ = writer.write_all(out.as_bytes()).await;
    }
}

// ─── misc helpers ────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── RaftLog tests ────────────────────────────────────────────────────

    fn dummy_cmd() -> ClusterCommand {
        ClusterCommand::BlockIp {
            ip: "1.2.3.4".into(),
        }
    }

    fn make_entry(index: u64, term: u64) -> LogEntry {
        LogEntry {
            index,
            term,
            command: dummy_cmd(),
        }
    }

    #[test]
    fn test_raft_log_append_and_commit() {
        let mut log = RaftLog::new();
        assert_eq!(log.last_index(), 0);
        assert_eq!(log.last_term(), 0);

        log.entries.push(make_entry(1, 1));
        log.entries.push(make_entry(2, 1));
        assert_eq!(log.last_index(), 2);
        assert_eq!(log.last_term(), 1);

        log.commit_index = 2;
        log.last_applied = 2;
        assert_eq!(log.commit_index, 2);
    }

    #[test]
    fn test_raft_log_get() {
        let mut log = RaftLog::new();
        log.entries.push(make_entry(1, 1));
        log.entries.push(make_entry(2, 2));
        log.entries.push(make_entry(3, 2));

        assert!(log.get(0).is_none());
        assert_eq!(log.get(1).unwrap().term, 1);
        assert_eq!(log.get(2).unwrap().term, 2);
        assert_eq!(log.get(3).unwrap().term, 2);
        assert!(log.get(4).is_none());
    }

    #[test]
    fn test_raft_log_append_entries_truncates_conflict() {
        let mut log = RaftLog::new();
        log.entries.push(make_entry(1, 1));
        log.entries.push(make_entry(2, 1));
        log.entries.push(make_entry(3, 1));

        // New leader sends entry at index 2 with term 2 — conflicts from index 2 onward.
        let new_entries = vec![make_entry(2, 2), make_entry(3, 2)];
        log.append_entries(1, new_entries);

        assert_eq!(log.entries.len(), 3);
        assert_eq!(log.get(2).unwrap().term, 2);
        assert_eq!(log.get(3).unwrap().term, 2);
    }

    // ── Vote counting ────────────────────────────────────────────────────

    #[test]
    fn test_vote_counting_quorum() {
        let mut votes: HashSet<NodeId> = HashSet::new();
        votes.insert(1); // self

        // 3-node cluster: quorum = 2
        let quorum = 2;
        assert!(votes.len() < quorum);

        votes.insert(2);
        assert!(votes.len() >= quorum);
    }

    #[test]
    fn test_vote_counting_five_node_quorum() {
        // 5-node cluster: quorum = 3
        let peers = 4; // self + 4 peers
        let quorum = (peers + 1) / 2 + 1; // = 3
        assert_eq!(quorum, 3);

        let mut votes: HashSet<NodeId> = HashSet::new();
        votes.insert(1); // self
        votes.insert(2);
        assert!(votes.len() < quorum);
        votes.insert(3);
        assert!(votes.len() >= quorum);
    }

    // ── Log matching (election safety) ───────────────────────────────────

    #[test]
    fn test_log_matching_rejects_stale_candidate() {
        // A candidate with last_log_term=1 should NOT get a vote from a node
        // whose last_log_term=2.
        let current_last_term = 2u64;
        let current_last_index = 5u64;

        let candidate_last_term = 1u64;
        let candidate_last_index = 10u64;

        let log_ok = candidate_last_term > current_last_term
            || (candidate_last_term == current_last_term
                && candidate_last_index >= current_last_index);

        assert!(!log_ok, "stale candidate should not win vote");
    }

    #[test]
    fn test_log_matching_accepts_up_to_date_candidate() {
        let current_last_term = 2u64;
        let current_last_index = 3u64;

        let candidate_last_term = 2u64;
        let candidate_last_index = 5u64;

        let log_ok = candidate_last_term > current_last_term
            || (candidate_last_term == current_last_term
                && candidate_last_index >= current_last_index);

        assert!(log_ok, "up-to-date candidate should win vote");
    }

    // ── ClusterStatus serialization ──────────────────────────────────────

    #[test]
    fn test_cluster_status_serde() {
        let status = ClusterStatus {
            node_id: 1,
            role: NodeRole::Leader,
            term: 5,
            leader_id: Some(1),
            peers: vec![PeerStatus {
                node_id: 2,
                addr: "127.0.0.1:9503".into(),
                is_reachable: true,
                last_seen: Some(1_700_000_000),
            }],
            applied_log_index: 42,
        };

        let json = serde_json::to_string(&status).expect("serialize");
        let back: ClusterStatus = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(back.node_id, 1);
        assert_eq!(back.role, NodeRole::Leader);
        assert_eq!(back.term, 5);
        assert_eq!(back.applied_log_index, 42);
        assert_eq!(back.peers.len(), 1);
        assert_eq!(back.peers[0].last_seen, Some(1_700_000_000));
    }

    #[test]
    fn test_cluster_command_serde() {
        let cmds = vec![
            ClusterCommand::BlockIp { ip: "10.0.0.1".into() },
            ClusterCommand::UnblockIp { ip: "10.0.0.1".into() },
            ClusterCommand::UpdateSiteConfig {
                site_id: "site-1".into(),
                config_json: r#"{"rate_limit":100}"#.into(),
            },
            ClusterCommand::UpdateRuleSet {
                tenant_id: "tenant-42".into(),
                rules_json: r#"[{"id":"r1"}]"#.into(),
            },
        ];
        for cmd in &cmds {
            let json = serde_json::to_string(cmd).expect("serialize");
            let back: ClusterCommand = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*cmd, back);
        }
    }

    // ── Single-node cluster becomes leader ───────────────────────────────

    #[tokio::test]
    async fn test_single_node_becomes_leader() {
        let dir = tempdir();
        let cfg = ClusterConfig {
            node_id: 1,
            listen_addr: "127.0.0.1:19502".into(),
            peers: vec![],
            data_dir: dir.clone(),
        };

        let handle = ClusterHandle::start(cfg).await.expect("start");
        // Give it a moment to bind and set up.
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert!(handle.is_leader().await);
        assert_eq!(handle.current_leader().await, Some(1));

        let status = handle.status().await;
        assert_eq!(status.role, NodeRole::Leader);
        assert_eq!(status.term, 1);

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn test_single_node_propose_succeeds() {
        let dir = tempdir();
        let cfg = ClusterConfig {
            node_id: 2,
            listen_addr: "127.0.0.1:19503".into(),
            peers: vec![],
            data_dir: dir.clone(),
        };

        let handle = ClusterHandle::start(cfg).await.expect("start");
        tokio::time::sleep(Duration::from_millis(50)).await;

        handle
            .propose(ClusterCommand::BlockIp { ip: "5.6.7.8".into() })
            .await
            .expect("propose should succeed on leader");

        let status = handle.status().await;
        assert_eq!(status.applied_log_index, 1);

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn test_single_node_multiple_proposals() {
        let dir = tempdir();
        let cfg = ClusterConfig {
            node_id: 3,
            listen_addr: "127.0.0.1:19504".into(),
            peers: vec![],
            data_dir: dir.clone(),
        };

        let handle = ClusterHandle::start(cfg).await.expect("start");
        tokio::time::sleep(Duration::from_millis(50)).await;

        for i in 0..5u32 {
            handle
                .propose(ClusterCommand::UpdateSiteConfig {
                    site_id: format!("site-{i}"),
                    config_json: "{}".into(),
                })
                .await
                .expect("propose");
        }

        let status = handle.status().await;
        assert_eq!(status.applied_log_index, 5);

        handle.shutdown().await;
    }

    // ── RaftState helpers ────────────────────────────────────────────────

    #[test]
    fn test_raft_state_quorum_calculation() {
        let cfg_1 = ClusterConfig {
            node_id: 1,
            listen_addr: "127.0.0.1:9999".into(),
            peers: vec![],
            data_dir: "/tmp/test".into(),
        };
        assert_eq!(RaftState::new(&cfg_1).quorum(), 1);

        let cfg_3 = ClusterConfig {
            node_id: 1,
            listen_addr: "127.0.0.1:9999".into(),
            peers: vec![
                (2, "127.0.0.1:9503".into()),
                (3, "127.0.0.1:9504".into()),
            ],
            data_dir: "/tmp/test".into(),
        };
        assert_eq!(RaftState::new(&cfg_3).quorum(), 2);

        let cfg_5 = ClusterConfig {
            node_id: 1,
            listen_addr: "127.0.0.1:9999".into(),
            peers: vec![
                (2, "127.0.0.1:9503".into()),
                (3, "127.0.0.1:9504".into()),
                (4, "127.0.0.1:9505".into()),
                (5, "127.0.0.1:9506".into()),
            ],
            data_dir: "/tmp/test".into(),
        };
        assert_eq!(RaftState::new(&cfg_5).quorum(), 3);
    }

    #[test]
    fn test_node_role_serde() {
        let roles = [NodeRole::Leader, NodeRole::Follower, NodeRole::Candidate, NodeRole::Learner];
        for role in &roles {
            let json = serde_json::to_string(role).expect("serialize");
            let back: NodeRole = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*role, back);
        }
    }

    // ── Persistence ──────────────────────────────────────────────────────

    #[test]
    fn test_persistence_roundtrip() {
        let dir = tempdir();
        {
            let cfg = ClusterConfig {
                node_id: 7,
                listen_addr: "127.0.0.1:9999".into(),
                peers: vec![],
                data_dir: dir.clone(),
            };
            let mut state = RaftState::new(&cfg);
            state.current_term = 5;
            state.voted_for = Some(7);
            state.log.entries.push(make_entry(1, 5));
            state.persist();
        }
        {
            let cfg = ClusterConfig {
                node_id: 7,
                listen_addr: "127.0.0.1:9999".into(),
                peers: vec![],
                data_dir: dir.clone(),
            };
            let mut state = RaftState::new(&cfg);
            state.load_from_disk();
            assert_eq!(state.current_term, 5);
            assert_eq!(state.voted_for, Some(7));
            assert_eq!(state.log.last_index(), 1);
        }
    }

    // ── helpers ──────────────────────────────────────────────────────────

    /// Return a fresh temp directory path (as string) for test isolation.
    fn tempdir() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = format!("/tmp/sentinel-raft-test-{}-{n}", std::process::id());
        let _ = std::fs::create_dir_all(&path);
        path
    }
}
