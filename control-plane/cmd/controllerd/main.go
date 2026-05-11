package main

import (
	"fmt"
	"os"
)

// controllerd — Sentinel WAF control-plane daemon.
// Responsibilities:
//   - gRPC API for data-plane nodes
//   - REST/gRPC API for dashboard & sentinelctl
//   - Raft-based config replication across HA cluster
//   - RBAC, audit log, multi-tenant orchestration
func main() {
	fmt.Println("controllerd starting…")
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	// TODO: load config, init storage, start gRPC + REST servers, join raft cluster
	return nil
}
