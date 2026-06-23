package main

import (
	"context"
	"fmt"
	"os"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
)

func main() {
	dbURL := os.Getenv("SENTINEL_DB_URL")
	if dbURL == "" {
		fmt.Fprintln(os.Stderr, "SENTINEL_DB_URL is required")
		os.Exit(1)
	}
	pool, err := db.Open(context.Background(), db.Config{URL: dbURL, MaxConns: 5, MinConns: 1})
	if err != nil { fmt.Println("connect:", err); os.Exit(1) }
	defer pool.Close()
	if err := db.SeedDev(context.Background(), pool); err != nil {
		fmt.Println("seed:", err); os.Exit(1)
	}
	fmt.Println("OK")
}
