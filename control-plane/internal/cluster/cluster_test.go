package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// freeAddr returns a host:port whose listener was just closed — best-effort
// way to grab a free port for tests.  Race window is small and tolerable here.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freeAddr: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// TestSingleNodeAutoLeader verifies that a single-node cluster (no peers)
// becomes leader immediately without any election timeout.
func TestSingleNodeAutoLeader(t *testing.T) {
	dir := t.TempDir()
	addr := freeAddr(t)

	cl, err := Start(Config{
		NodeID:     1,
		ListenAddr: addr,
		Peers:      nil,
		DataDir:    dir,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer cl.Stop()

	if !cl.IsLeader() {
		t.Fatalf("single-node should be leader instantly, got role=%s", cl.Status().Role)
	}
	id, _ := cl.LeaderHint()
	if id == nil || *id != 1 {
		t.Fatalf("LeaderHint=%v, want 1", id)
	}
}

// TestProposeAppliesOnSingleNode verifies that Propose commits + applies
// instantly on a single-node cluster, and that the Apply callback runs.
func TestProposeAppliesOnSingleNode(t *testing.T) {
	var applied atomic.Int64
	var seenKind atomic.Value

	cl, err := Start(Config{
		NodeID:     1,
		ListenAddr: freeAddr(t),
		DataDir:    t.TempDir(),
		Apply: func(cmd Command) error {
			applied.Add(1)
			seenKind.Store(string(cmd.Kind))
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer cl.Stop()

	payload, _ := json.Marshal(map[string]string{"site_id": "abc"})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := cl.Propose(ctx, Command{Kind: CmdSiteDelete, Payload: payload}); err != nil {
		t.Fatalf("Propose: %v", err)
	}

	if applied.Load() != 1 {
		t.Fatalf("Apply should have run once, got %d", applied.Load())
	}
	if got, _ := seenKind.Load().(string); got != string(CmdSiteDelete) {
		t.Fatalf("Apply saw kind=%q, want %q", got, CmdSiteDelete)
	}

	st := cl.Status()
	if st.LogLastIndex != 1 || st.LogCommitIndex != 1 || st.LogAppliedIndex != 1 {
		t.Fatalf("log indices want 1/1/1, got %d/%d/%d", st.LogLastIndex, st.LogCommitIndex, st.LogAppliedIndex)
	}
}

// TestPersistenceRestoresLog verifies that the persisted Raft state survives
// a restart of the same node.
func TestPersistenceRestoresLog(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "raft")
	addr := freeAddr(t)

	cl1, err := Start(Config{NodeID: 1, ListenAddr: addr, DataDir: dir})
	if err != nil {
		t.Fatalf("Start#1: %v", err)
	}
	payload, _ := json.Marshal(map[string]string{"x": "1"})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := cl1.Propose(ctx, Command{Kind: CmdSiteCreate, Payload: payload}); err != nil {
		t.Fatalf("Propose: %v", err)
	}
	cl1.Stop()

	cl2, err := Start(Config{NodeID: 1, ListenAddr: freeAddr(t), DataDir: dir})
	if err != nil {
		t.Fatalf("Start#2: %v", err)
	}
	defer cl2.Stop()
	st := cl2.Status()
	if st.LogLastIndex == 0 {
		t.Fatalf("restart should restore at least 1 log entry, got LogLastIndex=0")
	}
}

// TestThreeNodeElection brings up a 3-node cluster and verifies that exactly
// one node becomes leader, and that Propose on the leader commits via Raft.
func TestThreeNodeElection(t *testing.T) {
	addrs := []string{freeAddr(t), freeAddr(t), freeAddr(t)}
	peers := func(self NodeID) map[NodeID]string {
		m := map[NodeID]string{}
		for i, a := range addrs {
			id := NodeID(i + 1)
			if id == self {
				continue
			}
			m[id] = a
		}
		return m
	}

	var appliedCount [3]atomic.Int64
	nodes := make([]*Cluster, 3)
	var startErr error
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()
			node, err := Start(Config{
				NodeID:     NodeID(i + 1),
				ListenAddr: addrs[i],
				Peers:      peers(NodeID(i + 1)),
				DataDir:    t.TempDir(),
				Apply: func(cmd Command) error {
					appliedCount[i].Add(1)
					return nil
				},
			})
			if err != nil {
				startErr = err
				return
			}
			nodes[i] = node
		}()
	}
	wg.Wait()
	if startErr != nil {
		t.Fatalf("Start: %v", startErr)
	}
	defer func() {
		for _, n := range nodes {
			if n != nil {
				n.Stop()
			}
		}
	}()

	// Wait for a leader to emerge (election timeout is 400–700ms).
	deadline := time.Now().Add(5 * time.Second)
	var leader *Cluster
	for time.Now().Before(deadline) {
		leaderCount := 0
		for _, n := range nodes {
			if n.IsLeader() {
				leaderCount++
				leader = n
			}
		}
		if leaderCount == 1 {
			break
		}
		leader = nil
		time.Sleep(50 * time.Millisecond)
	}
	if leader == nil {
		t.Fatalf("no leader elected within 5s. Statuses: %v %v %v",
			nodes[0].Status().Role, nodes[1].Status().Role, nodes[2].Status().Role)
	}

	// Propose on the leader; confirm it replicates + applies on all nodes.
	payload, _ := json.Marshal(map[string]string{"k": "v"})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := leader.Propose(ctx, Command{Kind: CmdRuleCreate, Payload: payload}); err != nil {
		t.Fatalf("Propose on leader: %v", err)
	}

	// Wait for applies to propagate to all 3 nodes.
	propDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(propDeadline) {
		all := true
		for i := 0; i < 3; i++ {
			if appliedCount[i].Load() < 1 {
				all = false
				break
			}
		}
		if all {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("not all nodes applied: %d/%d/%d",
		appliedCount[0].Load(), appliedCount[1].Load(), appliedCount[2].Load())
}

// TestNotLeaderError verifies that proposing to a follower returns NotLeaderError.
func TestNotLeaderError(t *testing.T) {
	addrs := []string{freeAddr(t), freeAddr(t), freeAddr(t)}
	peers := func(self NodeID) map[NodeID]string {
		m := map[NodeID]string{}
		for i, a := range addrs {
			id := NodeID(i + 1)
			if id == self {
				continue
			}
			m[id] = a
		}
		return m
	}
	nodes := make([]*Cluster, 3)
	for i := 0; i < 3; i++ {
		n, err := Start(Config{
			NodeID:     NodeID(i + 1),
			ListenAddr: addrs[i],
			Peers:      peers(NodeID(i + 1)),
			DataDir:    t.TempDir(),
		})
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
		nodes[i] = n
	}
	defer func() {
		for _, n := range nodes {
			n.Stop()
		}
	}()

	// Wait for election to settle and find a follower.
	deadline := time.Now().Add(5 * time.Second)
	var follower *Cluster
	for time.Now().Before(deadline) {
		for _, n := range nodes {
			if !n.IsLeader() && n.Status().LeaderID != nil {
				follower = n
				break
			}
		}
		if follower != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if follower == nil {
		t.Skip("could not find a follower with known leader in time")
	}

	err := follower.Propose(context.Background(), Command{Kind: CmdRaftNoop, Payload: []byte("{}")})
	if err == nil {
		t.Fatalf("Propose on follower should fail, got nil")
	}
	if _, ok := err.(*NotLeaderError); !ok {
		t.Fatalf("want *NotLeaderError, got %T: %v", err, err)
	}
}

// TestRPCAuth verifies the inter-node RPC authentication: a frame sealed with
// the cluster secret is accepted by a node holding the same secret, and rejected
// when the secret differs or the body is tampered with. A node with no secret
// configured (single-node) round-trips without auth for backward compatibility.
func TestRPCAuth(t *testing.T) {
	signer := &Cluster{cfg: Config{Secret: "shared-cluster-secret"}}

	env, err := signer.seal(rpcMsg{Type: rpcRequestVote, Term: 7, CandidateID: 1})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if env.Auth == "" {
		t.Fatal("sealed envelope must carry an auth tag when a secret is set")
	}

	// Correct secret accepts.
	if _, err := signer.open(env); err != nil {
		t.Fatalf("valid tag rejected: %v", err)
	}

	// Wrong secret is rejected (forgery / spoofing without the shared key).
	attacker := &Cluster{cfg: Config{Secret: "wrong-secret"}}
	if _, err := attacker.open(env); err == nil {
		t.Fatal("frame under the wrong secret must be rejected")
	}

	// Tampered body (e.g. forging a higher term to win an election) is rejected.
	tampered := env
	tampered.Msg = []byte(`{"type":"RequestVote","term":99,"candidate_id":1}`)
	if _, err := signer.open(tampered); err == nil {
		t.Fatal("tampered body must be rejected")
	}

	// No secret configured (single-node): seal/open round-trips without auth.
	plain := &Cluster{cfg: Config{}}
	penv, err := plain.seal(rpcMsg{Type: rpcRequestVote, Term: 1})
	if err != nil {
		t.Fatalf("seal (no secret): %v", err)
	}
	if penv.Auth != "" {
		t.Fatal("no-secret envelope must not carry an auth tag")
	}
	if _, err := plain.open(penv); err != nil {
		t.Fatalf("no-secret round-trip failed: %v", err)
	}
}

// (compile-time: ensure fmt is imported for any sprintf usage we might add)
var _ = fmt.Sprintf
