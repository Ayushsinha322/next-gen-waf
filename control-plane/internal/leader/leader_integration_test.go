package leader

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"go.uber.org/zap"
)

// Integration tests for advisory-lock leader election.
//
// These need a real Postgres: the properties under test (exactly one leader,
// automatic failover when the holder goes away, membership visible to every node)
// are properties of the database's lock manager, not of this Go code. A fake pool
// would only test the mock.
//
// Run with a throwaway database:
//
//	docker run -d --rm --name pg -e POSTGRES_PASSWORD=testpass \
//	  -e POSTGRES_USER=sentinel -e POSTGRES_DB=sentinel -p 55434:5432 postgres:16-alpine
//	# apply internal/db/migrations/*.sql (goose Up sections), then:
//	SENTINEL_TEST_DB_URL='postgres://sentinel:testpass@127.0.0.1:55434/sentinel?sslmode=disable' \
//	  go test ./internal/leader/ -v
//
// Skipped when SENTINEL_TEST_DB_URL is unset.

func testPool(t *testing.T) Pool {
	t.Helper()
	url := os.Getenv("SENTINEL_TEST_DB_URL")
	if url == "" {
		t.Skip("SENTINEL_TEST_DB_URL not set — skipping leader-election integration test")
	}
	pool, err := db.Open(context.Background(), db.Config{URL: url, MaxConns: 10, MinConns: 2})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(pool.Close)

	lp, ok := pool.(Pool)
	if !ok {
		t.Fatal("pgx pool does not satisfy leader.Pool")
	}
	// Clean slate: no stale leader/member rows from a previous run.
	ctx := context.Background()
	if err := lp.Exec(ctx, `DELETE FROM cluster_leader`); err != nil {
		t.Fatalf("clear cluster_leader: %v", err)
	}
	if err := lp.Exec(ctx, `DELETE FROM cluster_members`); err != nil {
		t.Fatalf("clear cluster_members: %v", err)
	}
	return lp
}

// eventually polls until cond holds or the deadline passes.
func eventually(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for: %s", within, what)
}

func TestExactlyOneLeaderAmongContenders(t *testing.T) {
	pool := testPool(t)
	log := zap.NewNop()

	const n = 4
	electors := make([]*Elector, n)
	for i := 0; i < n; i++ {
		electors[i] = New(pool, nodeName(i), advertiseFor(i), log)
		electors[i].Start()
		t.Cleanup(electors[i].Stop)
	}

	countLeaders := func() int {
		c := 0
		for _, e := range electors {
			if e.IsLeader() {
				c++
			}
		}
		return c
	}

	eventually(t, 10*time.Second, "one elector to win", func() bool { return countLeaders() == 1 })

	// Hold it under observation: two nodes must never both believe they lead.
	for i := 0; i < 20; i++ {
		if got := countLeaders(); got != 1 {
			t.Fatalf("split brain: %d leaders among %d contenders", got, n)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Every node must agree on who the leader is.
	var leaderID string
	for _, e := range electors {
		if e.IsLeader() {
			leaderID = e.Status().NodeID
		}
	}
	eventually(t, 10*time.Second, "all nodes to agree on the leader", func() bool {
		for _, e := range electors {
			id, _, ok := e.Leader()
			if !ok || id != leaderID {
				return false
			}
		}
		return true
	})
}

// TestFailoverWhenLeaderStops is the property Raft was carrying all its complexity
// for. Here it falls out of the advisory lock: the holder goes away, Postgres
// releases the lock, and the next contender takes it.
func TestFailoverWhenLeaderStops(t *testing.T) {
	pool := testPool(t)
	log := zap.NewNop()

	a := New(pool, "node-a", "node-a:9501", log)
	b := New(pool, "node-b", "node-b:9501", log)
	a.Start()
	b.Start()
	// BOTH must be stopped, not just one. The leader pins a pool connection for the
	// duration of its lock, and pgxpool.Close() blocks until every acquired
	// connection is returned — so leaving an elector running deadlocks teardown.
	// Stop is idempotent, so stopping one twice is harmless.
	t.Cleanup(a.Stop)
	t.Cleanup(b.Stop)

	eventually(t, 10*time.Second, "an initial leader", func() bool {
		return a.IsLeader() != b.IsLeader() // exactly one
	})

	first, second := a, b
	if b.IsLeader() {
		first, second = b, a
	}

	// Stop the leader. Stop() resigns explicitly, which is what makes failover
	// fast rather than waiting for Postgres to reap the connection.
	first.Stop()

	eventually(t, 15*time.Second, "the survivor to take leadership", second.IsLeader)

	if first.IsLeader() {
		t.Error("the stopped node still reports itself leader")
	}
	// And the survivor advertises itself as leader to everyone else.
	eventually(t, 10*time.Second, "leader row to name the survivor", func() bool {
		id, _, ok := second.Leader()
		return ok && id == second.Status().NodeID
	})
}

func TestMembershipVisibleFromEveryNode(t *testing.T) {
	pool := testPool(t)
	log := zap.NewNop()

	a := New(pool, "member-a", "member-a:9501", log)
	b := New(pool, "member-b", "member-b:9501", log)
	a.Start()
	b.Start()
	t.Cleanup(a.Stop)
	t.Cleanup(b.Stop)

	ctx := context.Background()
	// Raft could not do this: a follower had no view of its peers at all.
	eventually(t, 10*time.Second, "both nodes to appear in membership from a follower's view", func() bool {
		ms, err := b.Members(ctx)
		if err != nil || len(ms) != 2 {
			return false
		}
		leaders, reachable := 0, 0
		for _, m := range ms {
			if m.IsLeader {
				leaders++
			}
			if m.Reachable {
				reachable++
			}
		}
		return leaders == 1 && reachable == 2
	})

	// A departing node removes itself, so the topology view shows no phantom.
	a.Stop()
	eventually(t, 10*time.Second, "the stopped node to leave membership", func() bool {
		ms, err := b.Members(ctx)
		return err == nil && len(ms) == 1 && ms[0].NodeID == "member-b"
	})
}

func TestStandaloneNilElectorWritesFreely(t *testing.T) {
	// A nil elector means no database is configured. Such a node must not refuse
	// writes — that was the old quorum gate's failure mode, blocking writes when
	// the control plane could not form a majority even though the data store was
	// fine.
	var e *Elector
	if !e.IsLeader() {
		t.Error("a nil elector must report leadership so a standalone node can write")
	}
	if st := e.Status(); st.Enabled || st.Role != "standalone" {
		t.Errorf("unexpected nil-elector status: %+v", st)
	}
	if _, _, ok := e.Leader(); ok {
		t.Error("a nil elector should report no leader")
	}
}

func nodeName(i int) string     { return "contender-" + string(rune('a'+i)) }
func advertiseFor(i int) string { return nodeName(i) + ":9501" }
