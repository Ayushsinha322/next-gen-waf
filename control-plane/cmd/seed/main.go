package main

import (
	"context"
	"fmt"
	"os"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
)

func main() {
	url := "postgres://sentinel:sentinel_dev@localhost:5432/sentinel?sslmode=disable"
	pool, err := db.Open(context.Background(), db.Config{URL: url, MaxConns: 5, MinConns: 1})
	if err != nil { fmt.Println("connect:", err); os.Exit(1) }
	defer pool.Close()
	if err := db.SeedDev(context.Background(), pool); err != nil {
		fmt.Println("seed:", err); os.Exit(1)
	}
	fmt.Println("OK")
}
