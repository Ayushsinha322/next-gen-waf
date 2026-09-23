package main

import (
	"testing"
	"time"
)

// A node that did not run a delete learns of it from the missing row, and from
// then refuses the deleted user's still-unexpired access tokens.
func TestADeletedUserIsSignedOutOnEveryNode(t *testing.T) {
	c := newSessionEpochCache()
	now := time.Now().UTC()
	issued := now.Add(-time.Minute)
	ids := func(xs ...string) map[string]struct{} {
		m := map[string]struct{}{}
		for _, x := range xs {
			m[x] = struct{}{}
		}
		return m
	}

	c.observeUsers(ids("alice", "bob"), now) // baseline only
	if !c.valid("bob", issued) {
		t.Fatal("baseline must not revoke anyone")
	}
	c.observeUsers(ids("alice", "carol"), now.Add(5*time.Second)) // bob deleted, carol new
	if c.valid("bob", issued) {
		t.Fatal("a deleted user's token must be refused")
	}
	if !c.valid("carol", now) || !c.valid("alice", issued) {
		t.Fatal("a new or remaining user must not be affected")
	}
	// After the longest token could have lived, the entry is dropped.
	c.observeUsers(ids("alice", "carol"), now.Add(goneRetention+time.Minute))
	if _, still := c.gone["bob"]; still {
		t.Fatal("gone entries must expire after goneRetention")
	}
	// The node that ran the delete refuses immediately.
	c.markDeleted("alice", now)
	if c.valid("alice", issued) {
		t.Fatal("markDeleted must refuse at once")
	}
}
