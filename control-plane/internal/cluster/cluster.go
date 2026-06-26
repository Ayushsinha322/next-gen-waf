// Package cluster implements a minimal Raft consensus layer for the
// control-plane.  Three or five controllerd nodes elect a leader; client
// writes must hit the leader (followers respond 503 with a hint to redirect).
// Reads can target any node because Postgres is the shared system of record.
//
// The design intentionally mirrors crates/sentinel-cluster (Rust) at the
// protocol level: TCP frame-per-line JSON, RaftRpc tagged enum, same command
// shape.  Re-implementing in Go keeps the control-plane self-contained — no
// CGo, no subprocess, no extra deploy artefacts.
package cluster

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ─── public types ────────────────────────────────────────────────────────────

type NodeID uint64

// Role of a node in the Raft state machine.
type Role string

const (
	RoleFollower  Role = "follower"
	RoleCandidate Role = "candidate"
	RoleLeader    Role = "leader"
)

// Config describes how a node joins (or forms) a cluster.
type Config struct {
	NodeID     NodeID
	ListenAddr string                 // host:port for inter-node RPC
	Peers      map[NodeID]string      // peer_id → host:port (empty = single-node)
	DataDir    string                 // persistent state location
	Apply      func(cmd Command) error // called on every committed entry
	Logger     *zap.Logger
	// Secret is a pre-shared key used to authenticate inter-node RPC (HMAC over
	// each frame). Required for multi-node clusters; empty disables auth (only
	// safe for single-node, where no RPC crosses the wire).
	Secret string
}

// CommandKind enumerates the operation categories the control-plane replicates.
// Payload is application-defined JSON (kept opaque to the Raft layer).
type CommandKind string

const (
	CmdSiteCreate     CommandKind = "site.create"
	CmdSiteUpdate     CommandKind = "site.update"
	CmdSiteDelete     CommandKind = "site.delete"
	CmdSiteStatus     CommandKind = "site.status"
	CmdRuleCreate     CommandKind = "rule.create"
	CmdRuleToggle     CommandKind = "rule.toggle"
	CmdRuleDelete     CommandKind = "rule.delete"
	CmdAlertAck       CommandKind = "alert.ack"
	CmdAlertResolve   CommandKind = "alert.resolve"
	CmdAPIKeyCreate   CommandKind = "apikey.create"
	CmdAPIKeyRevoke   CommandKind = "apikey.revoke"
	CmdUserCreate     CommandKind = "user.create"
	CmdRaftNoop       CommandKind = "raft.noop" // leader confirmation
)

// Command is a single replicated operation.
type Command struct {
	Kind    CommandKind     `json:"kind"`
	Payload json.RawMessage `json:"payload"`
}

// Status is a point-in-time snapshot for monitoring.
type Status struct {
	NodeID          NodeID            `json:"node_id"`
	Role            Role              `json:"role"`
	Term            uint64            `json:"term"`
	LeaderID        *NodeID           `json:"leader_id,omitempty"`
	Peers           []PeerStatus      `json:"peers"`
	LogLastIndex    uint64            `json:"log_last_index"`
	LogCommitIndex  uint64            `json:"log_commit_index"`
	LogAppliedIndex uint64            `json:"log_applied_index"`
}

type PeerStatus struct {
	NodeID      NodeID `json:"node_id"`
	Addr        string `json:"addr"`
	Reachable   bool   `json:"reachable"`
	LastSeenSec int64  `json:"last_seen_sec"`
}

// Errors returned by the cluster.
var (
	ErrNotLeader = errors.New("not the leader")
	ErrShutdown  = errors.New("cluster shut down")
	ErrTimeout   = errors.New("propose timed out")
)

// NotLeaderError carries the leader hint so callers can redirect.
type NotLeaderError struct {
	LeaderID   *NodeID
	LeaderAddr string
}

func (e *NotLeaderError) Error() string {
	if e.LeaderID != nil {
		return fmt.Sprintf("not leader (current leader: %d at %s)", *e.LeaderID, e.LeaderAddr)
	}
	return "not leader (leader unknown)"
}

// ─── internal types ──────────────────────────────────────────────────────────

type logEntry struct {
	Index   uint64  `json:"index"`
	Term    uint64  `json:"term"`
	Command Command `json:"command"`
}

type persistentState struct {
	CurrentTerm uint64     `json:"current_term"`
	VotedFor    *NodeID    `json:"voted_for,omitempty"`
	Log         []logEntry `json:"log"`
}

// Tagged JSON RPC envelope.
type rpcMsg struct {
	Type string `json:"type"`

	// RequestVote / VoteReply
	Term         uint64 `json:"term,omitempty"`
	CandidateID  NodeID `json:"candidate_id,omitempty"`
	LastLogIndex uint64 `json:"last_log_index,omitempty"`
	LastLogTerm  uint64 `json:"last_log_term,omitempty"`
	VoteGranted  bool   `json:"vote_granted,omitempty"`

	// AppendEntries
	LeaderID     NodeID     `json:"leader_id,omitempty"`
	PrevLogIndex uint64     `json:"prev_log_index,omitempty"`
	PrevLogTerm  uint64     `json:"prev_log_term,omitempty"`
	Entries      []logEntry `json:"entries,omitempty"`
	LeaderCommit uint64     `json:"leader_commit,omitempty"`

	// AppendEntriesReply
	Success    bool   `json:"success,omitempty"`
	MatchIndex uint64 `json:"match_index,omitempty"`
}

const (
	rpcRequestVote      = "RequestVote"
	rpcRequestVoteReply = "RequestVoteReply"
	rpcAppendEntries    = "AppendEntries"
	rpcAppendReply      = "AppendEntriesReply"
)

// ─── Cluster ─────────────────────────────────────────────────────────────────

// Cluster is the public handle returned by Start.
type Cluster struct {
	cfg Config
	log *zap.Logger

	mu       sync.RWMutex
	role     Role
	term     uint64
	votedFor *NodeID
	leaderID *NodeID

	// log + commit
	entries        []logEntry
	commitIndex    uint64
	lastApplied    uint64
	pendingApplies map[uint64]chan error // index → reply channel for local proposals

	// leader-only state
	nextIndex  map[NodeID]uint64
	matchIndex map[NodeID]uint64

	// peer health
	peerLastSeen map[NodeID]time.Time

	// shutdown
	ctx       context.Context
	cancel    context.CancelFunc
	listener  net.Listener
	listenWG  sync.WaitGroup
	tickerCh  chan struct{}
	resetElec chan struct{}
}

// Start opens the listener, restores persisted state, and begins running the
// Raft state machine.  The returned *Cluster is safe for concurrent use.
func Start(cfg Config) (*Cluster, error) {
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}
	if cfg.Apply == nil {
		cfg.Apply = func(Command) error { return nil }
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return nil, fmt.Errorf("cluster: mkdir data dir: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	c := &Cluster{
		cfg:            cfg,
		log:            cfg.Logger.With(zap.Uint64("node_id", uint64(cfg.NodeID))),
		role:           RoleFollower,
		nextIndex:      make(map[NodeID]uint64),
		matchIndex:     make(map[NodeID]uint64),
		peerLastSeen:   make(map[NodeID]time.Time),
		pendingApplies: make(map[uint64]chan error),
		ctx:            ctx,
		cancel:         cancel,
		resetElec:      make(chan struct{}, 1),
	}

	c.loadFromDisk()

	// Single-node cluster: become leader immediately, skip election.
	if len(cfg.Peers) == 0 {
		c.mu.Lock()
		c.becomeLeaderLocked()
		c.mu.Unlock()
	}

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("cluster: listen %s: %w", cfg.ListenAddr, err)
	}
	c.listener = listener

	c.listenWG.Add(1)
	go c.acceptLoop()
	go c.runLoop()

	c.log.Info("cluster started",
		zap.String("addr", cfg.ListenAddr),
		zap.Int("peers", len(cfg.Peers)),
		zap.String("role", string(c.role)),
	)
	return c, nil
}

// Stop terminates the Raft loops and closes the listener.
func (c *Cluster) Stop() {
	c.cancel()
	if c.listener != nil {
		_ = c.listener.Close()
	}
	c.listenWG.Wait()
}

// IsLeader returns true if this node believes it's the current leader.
func (c *Cluster) IsLeader() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.role == RoleLeader
}

// LeaderHint returns (id, addr) of the current leader, or (nil, "") if unknown.
func (c *Cluster) LeaderHint() (*NodeID, string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.leaderID == nil {
		return nil, ""
	}
	id := *c.leaderID
	if id == c.cfg.NodeID {
		return &id, c.cfg.ListenAddr
	}
	return &id, c.cfg.Peers[id]
}

// Status snapshots cluster state for monitoring.
func (c *Cluster) Status() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()

	peers := make([]PeerStatus, 0, len(c.cfg.Peers))
	for id, addr := range c.cfg.Peers {
		last := c.peerLastSeen[id]
		ps := PeerStatus{NodeID: id, Addr: addr}
		if !last.IsZero() {
			ps.LastSeenSec = last.Unix()
			ps.Reachable = time.Since(last) < 2*heartbeatInterval
		}
		peers = append(peers, ps)
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].NodeID < peers[j].NodeID })

	st := Status{
		NodeID:          c.cfg.NodeID,
		Role:            c.role,
		Term:            c.term,
		LeaderID:        c.leaderID,
		Peers:           peers,
		LogLastIndex:    c.lastIndexLocked(),
		LogCommitIndex:  c.commitIndex,
		LogAppliedIndex: c.lastApplied,
	}
	return st
}

// Propose submits a command for replication.  Returns *NotLeaderError if this
// node isn't the leader.  Blocks until the entry is committed and applied (or
// timeout).
func (c *Cluster) Propose(ctx context.Context, cmd Command) error {
	c.mu.Lock()
	if c.role != RoleLeader {
		hint, addr := c.leaderID, ""
		if hint != nil {
			addr = c.cfg.Peers[*hint]
		}
		c.mu.Unlock()
		return &NotLeaderError{LeaderID: hint, LeaderAddr: addr}
	}

	idx := c.lastIndexLocked() + 1
	entry := logEntry{Index: idx, Term: c.term, Command: cmd}
	c.entries = append(c.entries, entry)
	c.persistLocked()

	// Single-node fast path: commit immediately.
	if len(c.cfg.Peers) == 0 {
		c.commitIndex = idx
		c.mu.Unlock()
		return c.applyUpTo(idx)
	}

	ch := make(chan error, 1)
	c.pendingApplies[idx] = ch
	c.mu.Unlock()

	// Kick replication.
	c.broadcastAppendEntries()

	select {
	case err := <-ch:
		return err
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pendingApplies, idx)
		c.mu.Unlock()
		return ErrTimeout
	case <-c.ctx.Done():
		return ErrShutdown
	}
}

// ─── Raft main loop ──────────────────────────────────────────────────────────

const (
	heartbeatInterval     = 100 * time.Millisecond
	electionTimeoutMinMs  = 400
	electionTimeoutMaxMs  = 700
	rpcDialTimeout        = 200 * time.Millisecond
	rpcReadTimeout        = 500 * time.Millisecond
)

func (c *Cluster) runLoop() {
	rng := rand.New(rand.NewSource(time.Now().UnixNano() ^ int64(c.cfg.NodeID)))
	electionTimeout := c.randomElectionTimeout(rng)
	electionDeadline := time.Now().Add(electionTimeout)
	heartbeatTicker := time.NewTicker(heartbeatInterval)
	defer heartbeatTicker.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.resetElec:
			electionTimeout = c.randomElectionTimeout(rng)
			electionDeadline = time.Now().Add(electionTimeout)
		case <-heartbeatTicker.C:
			c.mu.RLock()
			isLeader := c.role == RoleLeader
			c.mu.RUnlock()
			if isLeader {
				c.broadcastAppendEntries()
			}
		case <-tick.C:
			c.mu.RLock()
			role := c.role
			c.mu.RUnlock()
			if role != RoleLeader && time.Now().After(electionDeadline) {
				c.startElection()
				electionTimeout = c.randomElectionTimeout(rng)
				electionDeadline = time.Now().Add(electionTimeout)
			}
		}
	}
}

func (c *Cluster) randomElectionTimeout(rng *rand.Rand) time.Duration {
	span := electionTimeoutMaxMs - electionTimeoutMinMs
	ms := electionTimeoutMinMs + rng.Intn(span)
	return time.Duration(ms) * time.Millisecond
}

func (c *Cluster) signalElectionReset() {
	select {
	case c.resetElec <- struct{}{}:
	default:
	}
}

// ─── elections ───────────────────────────────────────────────────────────────

func (c *Cluster) startElection() {
	c.mu.Lock()
	if c.role == RoleLeader {
		c.mu.Unlock()
		return
	}
	c.term++
	c.role = RoleCandidate
	c.votedFor = &c.cfg.NodeID
	c.leaderID = nil
	term := c.term
	lastIdx := c.lastIndexLocked()
	lastTerm := c.lastTermLocked()
	c.persistLocked()
	c.mu.Unlock()

	c.log.Info("starting election", zap.Uint64("term", term))

	votes := 1 // self
	var voteMu sync.Mutex
	var wg sync.WaitGroup

	for id, addr := range c.cfg.Peers {
		wg.Add(1)
		go func(peerID NodeID, peerAddr string) {
			defer wg.Done()
			reply, err := c.sendRPC(peerAddr, rpcMsg{
				Type:         rpcRequestVote,
				Term:         term,
				CandidateID:  c.cfg.NodeID,
				LastLogIndex: lastIdx,
				LastLogTerm:  lastTerm,
			})
			if err != nil {
				return
			}
			c.markPeerSeen(peerID)
			c.mu.Lock()
			if reply.Term > c.term {
				c.becomeFollowerLocked(reply.Term)
				c.mu.Unlock()
				return
			}
			stillCandidate := c.role == RoleCandidate && c.term == term
			c.mu.Unlock()
			if !stillCandidate {
				return
			}
			if reply.VoteGranted {
				voteMu.Lock()
				votes++
				granted := votes
				voteMu.Unlock()
				if granted >= c.quorum() {
					c.mu.Lock()
					if c.role == RoleCandidate && c.term == term {
						c.becomeLeaderLocked()
					}
					c.mu.Unlock()
					// Send immediate heartbeat to assert leadership.
					c.broadcastAppendEntries()
				}
			}
		}(id, addr)
	}
	wg.Wait()
}

func (c *Cluster) quorum() int {
	return (len(c.cfg.Peers)+1)/2 + 1
}

// becomeFollowerLocked must be called with c.mu held.
func (c *Cluster) becomeFollowerLocked(term uint64) {
	c.term = term
	c.role = RoleFollower
	c.votedFor = nil
	c.leaderID = nil
	c.persistLocked()
	c.signalElectionReset()
}

// becomeLeaderLocked must be called with c.mu held.
func (c *Cluster) becomeLeaderLocked() {
	c.log.Info("becoming leader", zap.Uint64("term", c.term))
	c.role = RoleLeader
	id := c.cfg.NodeID
	c.leaderID = &id
	next := c.lastIndexLocked() + 1
	for peerID := range c.cfg.Peers {
		c.nextIndex[peerID] = next
		c.matchIndex[peerID] = 0
	}
}

// ─── log replication ─────────────────────────────────────────────────────────

func (c *Cluster) broadcastAppendEntries() {
	c.mu.RLock()
	if c.role != RoleLeader {
		c.mu.RUnlock()
		return
	}
	term := c.term
	commit := c.commitIndex
	c.mu.RUnlock()

	for peerID, peerAddr := range c.cfg.Peers {
		go c.sendAppendEntriesTo(peerID, peerAddr, term, commit)
	}
}

func (c *Cluster) sendAppendEntriesTo(peerID NodeID, peerAddr string, term, commit uint64) {
	c.mu.RLock()
	if c.role != RoleLeader || c.term != term {
		c.mu.RUnlock()
		return
	}
	nextIdx := c.nextIndex[peerID]
	if nextIdx == 0 {
		nextIdx = 1
	}
	prevIndex := nextIdx - 1
	prevTerm := uint64(0)
	if prevIndex > 0 {
		if e := c.getEntryLocked(prevIndex); e != nil {
			prevTerm = e.Term
		}
	}
	var entries []logEntry
	last := c.lastIndexLocked()
	for i := nextIdx; i <= last; i++ {
		if e := c.getEntryLocked(i); e != nil {
			entries = append(entries, *e)
		}
	}
	c.mu.RUnlock()

	reply, err := c.sendRPC(peerAddr, rpcMsg{
		Type:         rpcAppendEntries,
		Term:         term,
		LeaderID:     c.cfg.NodeID,
		PrevLogIndex: prevIndex,
		PrevLogTerm:  prevTerm,
		Entries:      entries,
		LeaderCommit: commit,
	})
	if err != nil {
		return
	}
	c.markPeerSeen(peerID)

	c.mu.Lock()
	defer c.mu.Unlock()
	if reply.Term > c.term {
		c.becomeFollowerLocked(reply.Term)
		return
	}
	if c.role != RoleLeader || c.term != term {
		return
	}
	if reply.Success {
		if len(entries) > 0 {
			c.matchIndex[peerID] = reply.MatchIndex
			c.nextIndex[peerID] = reply.MatchIndex + 1
		}
		c.advanceCommitLocked()
	} else {
		// Walk nextIndex back on inconsistency.
		if c.nextIndex[peerID] > 1 {
			c.nextIndex[peerID]--
		}
	}
}

func (c *Cluster) advanceCommitLocked() {
	last := c.lastIndexLocked()
	for n := last; n > c.commitIndex; n-- {
		entry := c.getEntryLocked(n)
		if entry == nil || entry.Term != c.term {
			continue
		}
		count := 1 // self
		for peerID := range c.cfg.Peers {
			if c.matchIndex[peerID] >= n {
				count++
			}
		}
		if count >= c.quorum() {
			c.commitIndex = n
			break
		}
	}
	go c.applyCommitted()
}

func (c *Cluster) applyCommitted() {
	for {
		c.mu.Lock()
		if c.lastApplied >= c.commitIndex {
			c.mu.Unlock()
			return
		}
		next := c.lastApplied + 1
		entry := c.getEntryLocked(next)
		if entry == nil {
			c.mu.Unlock()
			return
		}
		cmd := entry.Command
		c.lastApplied = next
		ch, hasPending := c.pendingApplies[next]
		if hasPending {
			delete(c.pendingApplies, next)
		}
		c.mu.Unlock()

		err := c.cfg.Apply(cmd)
		if hasPending {
			ch <- err
		}
		if err != nil {
			c.log.Warn("apply failed", zap.Uint64("index", next), zap.Error(err))
		}
	}
}

func (c *Cluster) applyUpTo(idx uint64) error {
	c.applyCommitted()
	c.mu.RLock()
	applied := c.lastApplied
	c.mu.RUnlock()
	if applied < idx {
		return errors.New("apply: pending")
	}
	return nil
}

// ─── RPC authentication ──────────────────────────────────────────────────────
//
// Every inter-node frame is wrapped in an envelope carrying an HMAC-SHA256 tag
// over the exact inner-message bytes, keyed by the shared cluster secret. This
// authenticates the peer and detects tampering without ever putting the secret
// on the wire — so a node that can merely reach the port can no longer forge log
// entries or spoof votes. (It does not provide confidentiality; run the cluster
// on a trusted/isolated network, or front it with TLS, if that is required.)

type rpcEnvelope struct {
	Auth string          `json:"auth,omitempty"`
	Msg  json.RawMessage `json:"msg"`
}

func (c *Cluster) authTag(msg []byte) string {
	mac := hmac.New(sha256.New, []byte(c.cfg.Secret))
	mac.Write(msg)
	return hex.EncodeToString(mac.Sum(nil))
}

// seal marshals an RPC message and, when a secret is configured, tags it.
func (c *Cluster) seal(msg rpcMsg) (rpcEnvelope, error) {
	body, err := json.Marshal(msg)
	if err != nil {
		return rpcEnvelope{}, err
	}
	env := rpcEnvelope{Msg: body}
	if c.cfg.Secret != "" {
		env.Auth = c.authTag(body)
	}
	return env, nil
}

// open verifies the envelope's tag (constant-time, when a secret is configured)
// and returns the inner RPC message.
func (c *Cluster) open(env rpcEnvelope) (rpcMsg, error) {
	if c.cfg.Secret != "" {
		if !hmac.Equal([]byte(c.authTag(env.Msg)), []byte(env.Auth)) {
			return rpcMsg{}, errors.New("cluster: RPC authentication failed")
		}
	}
	var msg rpcMsg
	if err := json.Unmarshal(env.Msg, &msg); err != nil {
		return rpcMsg{}, err
	}
	return msg, nil
}

// ─── RPC server ──────────────────────────────────────────────────────────────

func (c *Cluster) acceptLoop() {
	defer c.listenWG.Done()
	for {
		conn, err := c.listener.Accept()
		if err != nil {
			if c.ctx.Err() != nil {
				return
			}
			c.log.Warn("accept error", zap.Error(err))
			continue
		}
		go c.serveConn(conn)
	}
}

func (c *Cluster) serveConn(conn net.Conn) {
	defer conn.Close()
	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)
	for {
		var env rpcEnvelope
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if err := dec.Decode(&env); err != nil {
			return
		}
		req, err := c.open(env)
		if err != nil {
			c.log.Warn("rejecting RPC", zap.Error(err), zap.String("remote", conn.RemoteAddr().String()))
			return
		}
		reply, ok := c.handleRPC(req)
		if !ok {
			return
		}
		out, err := c.seal(reply)
		if err != nil {
			return
		}
		_ = conn.SetWriteDeadline(time.Now().Add(rpcReadTimeout))
		if err := enc.Encode(out); err != nil {
			return
		}
	}
}

func (c *Cluster) handleRPC(req rpcMsg) (rpcMsg, bool) {
	switch req.Type {
	case rpcRequestVote:
		return c.handleRequestVote(req), true
	case rpcAppendEntries:
		return c.handleAppendEntries(req), true
	default:
		return rpcMsg{}, false
	}
}

func (c *Cluster) handleRequestVote(req rpcMsg) rpcMsg {
	c.mu.Lock()
	defer c.mu.Unlock()
	reply := rpcMsg{Type: rpcRequestVoteReply, Term: c.term, VoteGranted: false}

	if req.Term < c.term {
		return reply
	}
	if req.Term > c.term {
		c.becomeFollowerLocked(req.Term)
		reply.Term = c.term
	}

	// Election restriction: candidate's log must be at least as up-to-date.
	myLastIdx := c.lastIndexLocked()
	myLastTerm := c.lastTermLocked()
	upToDate := req.LastLogTerm > myLastTerm ||
		(req.LastLogTerm == myLastTerm && req.LastLogIndex >= myLastIdx)

	if (c.votedFor == nil || *c.votedFor == req.CandidateID) && upToDate {
		v := req.CandidateID
		c.votedFor = &v
		c.persistLocked()
		c.signalElectionReset()
		reply.VoteGranted = true
	}
	return reply
}

func (c *Cluster) handleAppendEntries(req rpcMsg) rpcMsg {
	c.mu.Lock()
	defer c.mu.Unlock()
	reply := rpcMsg{Type: rpcAppendReply, Term: c.term, Success: false}

	if req.Term < c.term {
		return reply
	}
	if req.Term > c.term || c.role != RoleFollower {
		c.becomeFollowerLocked(req.Term)
	}
	c.term = req.Term
	reply.Term = c.term
	lid := req.LeaderID
	c.leaderID = &lid
	c.signalElectionReset()

	// Consistency check on prev entry.
	if req.PrevLogIndex > 0 {
		entry := c.getEntryLocked(req.PrevLogIndex)
		if entry == nil || entry.Term != req.PrevLogTerm {
			return reply
		}
	}

	// Append, truncating any conflicting suffix.
	for i, e := range req.Entries {
		idx := req.PrevLogIndex + 1 + uint64(i)
		existing := c.getEntryLocked(idx)
		if existing != nil && existing.Term != e.Term {
			c.truncateLocked(idx)
			existing = nil
		}
		if existing == nil {
			c.entries = append(c.entries, e)
		}
	}
	if len(req.Entries) > 0 {
		c.persistLocked()
	}

	if req.LeaderCommit > c.commitIndex {
		last := c.lastIndexLocked()
		if req.LeaderCommit < last {
			c.commitIndex = req.LeaderCommit
		} else {
			c.commitIndex = last
		}
		go c.applyCommitted()
	}

	reply.Success = true
	reply.MatchIndex = c.lastIndexLocked()
	return reply
}

// ─── RPC client ──────────────────────────────────────────────────────────────

func (c *Cluster) sendRPC(addr string, msg rpcMsg) (rpcMsg, error) {
	d := net.Dialer{Timeout: rpcDialTimeout}
	conn, err := d.DialContext(c.ctx, "tcp", addr)
	if err != nil {
		return rpcMsg{}, err
	}
	defer conn.Close()
	out, err := c.seal(msg)
	if err != nil {
		return rpcMsg{}, err
	}
	_ = conn.SetWriteDeadline(time.Now().Add(rpcReadTimeout))
	if err := json.NewEncoder(conn).Encode(out); err != nil {
		return rpcMsg{}, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(rpcReadTimeout))
	var replyEnv rpcEnvelope
	if err := json.NewDecoder(conn).Decode(&replyEnv); err != nil {
		return rpcMsg{}, err
	}
	return c.open(replyEnv)
}

func (c *Cluster) markPeerSeen(id NodeID) {
	c.mu.Lock()
	c.peerLastSeen[id] = time.Now()
	c.mu.Unlock()
}

// ─── log helpers (must be called with c.mu held appropriately) ───────────────

func (c *Cluster) lastIndexLocked() uint64 {
	if len(c.entries) == 0 {
		return 0
	}
	return c.entries[len(c.entries)-1].Index
}

func (c *Cluster) lastTermLocked() uint64 {
	if len(c.entries) == 0 {
		return 0
	}
	return c.entries[len(c.entries)-1].Term
}

func (c *Cluster) getEntryLocked(idx uint64) *logEntry {
	if idx == 0 || len(c.entries) == 0 {
		return nil
	}
	first := c.entries[0].Index
	if idx < first {
		return nil
	}
	off := int(idx - first)
	if off >= len(c.entries) {
		return nil
	}
	return &c.entries[off]
}

func (c *Cluster) truncateLocked(fromIdx uint64) {
	if len(c.entries) == 0 {
		return
	}
	first := c.entries[0].Index
	if fromIdx < first {
		c.entries = nil
		return
	}
	off := int(fromIdx - first)
	if off > len(c.entries) {
		return
	}
	c.entries = c.entries[:off]
}

// ─── persistence ─────────────────────────────────────────────────────────────

func (c *Cluster) persistLocked() {
	ps := persistentState{
		CurrentTerm: c.term,
		VotedFor:    c.votedFor,
		Log:         c.entries,
	}
	data, err := json.Marshal(&ps)
	if err != nil {
		c.log.Warn("persist marshal", zap.Error(err))
		return
	}
	path := filepath.Join(c.cfg.DataDir, "raft_state.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		c.log.Warn("persist write", zap.Error(err))
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		c.log.Warn("persist rename", zap.Error(err))
	}
}

func (c *Cluster) loadFromDisk() {
	path := filepath.Join(c.cfg.DataDir, "raft_state.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var ps persistentState
	if err := json.Unmarshal(data, &ps); err != nil {
		c.log.Warn("loadFromDisk unmarshal", zap.Error(err))
		return
	}
	c.mu.Lock()
	c.term = ps.CurrentTerm
	c.votedFor = ps.VotedFor
	c.entries = ps.Log
	c.mu.Unlock()
	c.log.Info("loaded persisted Raft state",
		zap.Uint64("term", c.term),
		zap.Int("log_entries", len(c.entries)),
	)
}
