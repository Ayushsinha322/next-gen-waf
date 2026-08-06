// Package leader provides single-writer election for the control plane, built on
// a Postgres session-scoped advisory lock.
//
// # Why this replaced Raft
//
// The control plane previously ran a hand-rolled Raft implementation
// (internal/cluster, ~975 lines: terms, elections, an authenticated RPC layer,
// a replicated log). It was removed rather than fixed, because the log it
// replicated carried nothing:
//
//   - The state machine was a no-op. By apply time the leader had already written
//     through to Postgres, and followers re-read from Postgres on demand.
//   - There was no snapshotting or compaction, so the log grew without bound.
//   - It was only ever exercised in a single process, while carrying the full
//     failure surface of a consensus protocol.
//   - Its quorum gate was actively harmful: losing 2 of 3 control-plane nodes
//     refused every write even while Postgres — itself HA with its own synchronous
//     quorum — was healthy and writable.
//
// Postgres was always the real source of truth, so leadership is now derived from
// it directly. Contenders race for one advisory lock; the winner is the single
// writer for as long as its connection lives. If it crashes or is partitioned, the
// server releases the lock — no lease to expire, no clock to trust, no second
// quorum to lose independently of the database.
//
// # What leadership is still for
//
// Not correctness of the data: Postgres constraints and transactions provide that.
// Leadership exists so that (a) writes funnel through one node, keeping
// audit/config-generation ordering simple, and (b) singleton background jobs
// (cert monitor, disk monitor, node-health monitor) run on exactly one node
// instead of all of them.
package leader

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"go.uber.org/zap"
)

// LockKey is the advisory-lock key for control-plane write leadership. Any stable
// constant works; it must not collide with other advisory-lock users in the same
// database (the audit chain uses a different namespace and the two-argument form).
const LockKey int64 = 0x53454E54494E4C31 // "SENTINL1"

// Tunables. Deliberately not configurable: the failover characteristics of an
// advisory lock are governed by connection liveness, not by these intervals.
const (
	// heartbeatInterval is how often the leader confirms its lock-owning
	// connection and refreshes the advisory leader row.
	heartbeatInterval = 3 * time.Second
	// campaignInterval is how often a follower retries acquiring the lock.
	campaignInterval = 2 * time.Second
	// opTimeout bounds each individual database operation.
	opTimeout = 5 * time.Second
)

// Pool is what the elector needs from the database layer.
type Pool interface {
	db.AdvisoryLocker
	db.GlobalQuerier
}

// Status is a point-in-time view for monitoring and the cluster API.
type Status struct {
	// Enabled is false when no database is configured, in which case the node is
	// a standalone writer.
	Enabled bool   `json:"enabled"`
	NodeID  string `json:"node_id"`
	// Role is "leader", "follower", or "standalone".
	Role string `json:"role"`
	// LeaderID / LeaderAddr describe the current leader as last observed. Empty
	// when no leader has been seen yet.
	LeaderID   string `json:"leader_id,omitempty"`
	LeaderAddr string `json:"leader_addr,omitempty"`
	// SinceUnix is when this node last changed role.
	SinceUnix int64 `json:"since_unix"`
}

// Elector campaigns for write leadership and tracks who currently holds it.
type Elector struct {
	pool      Pool
	nodeID    string
	advertise string
	log       *zap.Logger

	isLeader atomic.Bool
	// changedAt is a Unix timestamp of the last role transition.
	changedAt atomic.Int64

	mu         sync.RWMutex
	leaderID   string
	leaderAddr string

	// session is the held lock, non-nil only while leader.
	sessionMu sync.Mutex
	session   *db.AdvisorySession

	stop     chan struct{}
	stopped  chan struct{}
	stopOnce sync.Once
}

// NodeID resolves this node's stable identity: SENTINEL_NODE_ID, else the
// Kubernetes pod name, else the hostname.
func NodeID() string {
	for _, env := range []string{"SENTINEL_NODE_ID", "POD_NAME", "HOSTNAME"} {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			return v
		}
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unknown"
}

// New creates an elector. `advertise` is the host:port peers should forward writes
// to (this node's REST address as reachable by other nodes).
func New(pool Pool, nodeID, advertise string, log *zap.Logger) *Elector {
	e := &Elector{
		pool:      pool,
		nodeID:    nodeID,
		advertise: advertise,
		log:       log,
		stop:      make(chan struct{}),
		stopped:   make(chan struct{}),
	}
	e.changedAt.Store(time.Now().Unix())
	return e
}

// Start begins campaigning in the background. Returns immediately.
func (e *Elector) Start() {
	go e.run()
}

// Stop relinquishes leadership (if held) and halts campaigning. Idempotent.
//
// Releasing the lock explicitly matters for rollout speed: without it the
// successor would wait for Postgres to notice the dropped connection, adding
// seconds of write unavailability to every deploy.
//
// Callers MUST call this. While leader, the elector holds one pool connection for
// the lifetime of its lock, and closing a pgx pool blocks until every acquired
// connection is returned — so an elector left running deadlocks pool shutdown.
func (e *Elector) Stop() {
	e.stopOnce.Do(func() {
		close(e.stop)
		<-e.stopped
	})
}

// IsLeader reports whether this node currently holds write leadership.
func (e *Elector) IsLeader() bool {
	if e == nil {
		return true // no clustering configured: standalone node writes freely
	}
	return e.isLeader.Load()
}

// Leader returns the last observed leader's node ID and advertise address.
// ok is false when no leader has been observed.
func (e *Elector) Leader() (nodeID, addr string, ok bool) {
	if e == nil {
		return "", "", false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.leaderID == "" {
		return "", "", false
	}
	return e.leaderID, e.leaderAddr, true
}

// Status snapshots state for monitoring.
func (e *Elector) Status() Status {
	if e == nil {
		return Status{Enabled: false, Role: "standalone"}
	}
	id, addr, _ := e.Leader()
	role := "follower"
	if e.isLeader.Load() {
		role = "leader"
	}
	return Status{
		Enabled:    true,
		NodeID:     e.nodeID,
		Role:       role,
		LeaderID:   id,
		LeaderAddr: addr,
		SinceUnix:  e.changedAt.Load(),
	}
}

func (e *Elector) run() {
	defer close(e.stopped)
	// Campaign immediately so a cold start does not wait a full interval.
	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-e.stop:
			e.resign()
			shutCtx, shutCancel := context.WithTimeout(context.Background(), opTimeout)
			e.forgetMember(shutCtx)
			shutCancel()
			return
		case <-timer.C:
		}

		// Record this node's liveness regardless of role.
		hbCtx, hbCancel := context.WithTimeout(context.Background(), opTimeout)
		e.heartbeatMember(hbCtx)
		hbCancel()

		next := campaignInterval
		if e.isLeader.Load() {
			if e.confirmLeadership() {
				next = heartbeatInterval
			} else {
				// Lost the lock — demote and campaign again promptly.
				e.demote("lock lost")
				next = campaignInterval
			}
		} else if e.campaign() {
			next = heartbeatInterval
		} else {
			e.observeLeader()
		}
		timer.Reset(next)
	}
}

// campaign tries to take the lock. Returns true if this node is now leader.
func (e *Elector) campaign() bool {
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()

	sess, err := e.pool.TryAdvisoryLock(ctx, LockKey)
	if err != nil {
		// Postgres unreachable. Stay a follower; without the database this node
		// could not serve a write anyway.
		e.log.Warn("leader election: cannot reach database to campaign", zap.Error(err))
		return false
	}
	if sess == nil {
		return false // another node holds it
	}

	e.sessionMu.Lock()
	e.session = sess
	e.sessionMu.Unlock()

	e.isLeader.Store(true)
	e.changedAt.Store(time.Now().Unix())
	e.setLeader(e.nodeID, e.advertise)
	e.publishLeader(ctx)

	e.log.Info("acquired write leadership",
		zap.String("node_id", e.nodeID),
		zap.String("advertise", e.advertise))
	return true
}

// confirmLeadership verifies the lock-owning connection is still alive and
// refreshes the advisory leader row. Returns false if leadership was lost.
func (e *Elector) confirmLeadership() bool {
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()

	e.sessionMu.Lock()
	sess := e.session
	e.sessionMu.Unlock()
	if sess == nil {
		return false
	}
	if err := sess.Ping(ctx); err != nil {
		e.log.Warn("leader election: lock connection failed", zap.Error(err))
		return false
	}
	e.publishLeader(ctx)
	return true
}

// publishLeader refreshes the advisory row followers read to find the leader.
// Failure is non-fatal: the lock, not this row, is the authority on leadership.
func (e *Elector) publishLeader(ctx context.Context) {
	err := e.pool.Exec(ctx, `
		INSERT INTO cluster_leader (id, node_id, advertise, acquired_at, heartbeat_at)
		VALUES (true, $1, $2, now(), now())
		ON CONFLICT (id) DO UPDATE
		  SET node_id      = EXCLUDED.node_id,
		      advertise    = EXCLUDED.advertise,
		      heartbeat_at = now(),
		      acquired_at  = CASE
		                       WHEN cluster_leader.node_id = EXCLUDED.node_id
		                       THEN cluster_leader.acquired_at
		                       ELSE now()
		                     END`,
		e.nodeID, e.advertise)
	if err != nil {
		e.log.Warn("leader election: publishing leader row failed", zap.Error(err))
	}
}

// observeLeader refreshes this follower's view of who leads, for write forwarding.
func (e *Elector) observeLeader() {
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()

	var nodeID, advertise string
	err := e.pool.QueryRowGlobal(ctx,
		`SELECT node_id, advertise FROM cluster_leader WHERE id = true`).Scan(&nodeID, &advertise)
	if err != nil {
		// No leader row yet (fresh cluster) or the database is unreachable. Either
		// way we have no hint to offer; forwarding will answer 503 and be retried.
		e.setLeader("", "")
		return
	}
	e.setLeader(nodeID, advertise)
}

// Member is one control-plane node as recorded in shared state.
type Member struct {
	NodeID      string `json:"node_id"`
	Advertise   string `json:"addr"`
	IsLeader    bool   `json:"is_leader"`
	LastSeenSec int64  `json:"last_seen_sec"`
	// Reachable is derived: a node whose heartbeat is older than
	// MemberStaleAfter is presumed down.
	Reachable bool `json:"reachable"`
}

// MemberStaleAfter is how long without a heartbeat before a node is presumed
// down. Generous relative to heartbeatInterval so a brief GC pause or slow query
// does not flap the topology view.
const MemberStaleAfter = 20 * time.Second

// heartbeatMember records this node's liveness. Every node does this, leader and
// follower alike — unlike Raft, which only let the leader observe peers.
func (e *Elector) heartbeatMember(ctx context.Context) {
	err := e.pool.Exec(ctx, `
		INSERT INTO cluster_members (node_id, advertise, is_leader, started_at, last_seen)
		VALUES ($1, $2, $3, now(), now())
		ON CONFLICT (node_id) DO UPDATE
		  SET advertise = EXCLUDED.advertise,
		      is_leader = EXCLUDED.is_leader,
		      last_seen = now()`,
		e.nodeID, e.advertise, e.isLeader.Load())
	if err != nil {
		e.log.Warn("leader election: member heartbeat failed", zap.Error(err))
	}
}

// Members lists the control-plane nodes and their liveness, newest heartbeat
// first. Returns nil when the database is unreachable.
func (e *Elector) Members(ctx context.Context) ([]Member, error) {
	if e == nil {
		return nil, nil
	}
	rows, err := e.pool.QueryGlobal(ctx, `
		SELECT node_id, advertise, is_leader,
		       GREATEST(0, EXTRACT(EPOCH FROM (now() - last_seen))::bigint)
		  FROM cluster_members
		 ORDER BY node_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Member
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.NodeID, &m.Advertise, &m.IsLeader, &m.LastSeenSec); err != nil {
			return nil, err
		}
		m.Reachable = time.Duration(m.LastSeenSec)*time.Second < MemberStaleAfter
		out = append(out, m)
	}
	return out, rows.Err()
}

// forgetMember removes this node's row on clean shutdown so the topology view does
// not show a phantom node until its heartbeat goes stale.
func (e *Elector) forgetMember(ctx context.Context) {
	if err := e.pool.Exec(ctx,
		`DELETE FROM cluster_members WHERE node_id = $1`, e.nodeID); err != nil {
		e.log.Warn("leader election: clearing member row failed", zap.Error(err))
	}
}

func (e *Elector) setLeader(id, addr string) {
	e.mu.Lock()
	e.leaderID, e.leaderAddr = id, addr
	e.mu.Unlock()
}

func (e *Elector) demote(reason string) {
	e.isLeader.Store(false)
	e.changedAt.Store(time.Now().Unix())
	e.releaseSession()
	e.setLeader("", "")
	e.log.Warn("lost write leadership", zap.String("reason", reason), zap.String("node_id", e.nodeID))
}

// resign gives up leadership cleanly on shutdown.
func (e *Elector) resign() {
	if !e.isLeader.Load() {
		return
	}
	e.isLeader.Store(false)
	// Clear the advisory row so followers stop forwarding here before the process
	// exits, then drop the lock so a successor can take over immediately rather
	// than waiting for Postgres to reap the connection.
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	if err := e.pool.Exec(ctx,
		`DELETE FROM cluster_leader WHERE id = true AND node_id = $1`, e.nodeID); err != nil {
		e.log.Warn("leader election: clearing leader row on resign failed", zap.Error(err))
	}
	e.releaseSession()
	e.log.Info("resigned write leadership", zap.String("node_id", e.nodeID))
}

func (e *Elector) releaseSession() {
	e.sessionMu.Lock()
	sess := e.session
	e.session = nil
	e.sessionMu.Unlock()
	if sess == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	sess.Unlock(ctx)
}

// ErrNotLeader is returned by guards when this node may not perform a write.
var ErrNotLeader = errors.New("leader: this node is not the write leader")
