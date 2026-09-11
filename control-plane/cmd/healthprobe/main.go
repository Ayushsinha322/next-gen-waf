// healthprobe is a container healthcheck for our distroless images.
//
// Why this exists: sentinel-dataplane and sentinel-controlplane run on
// gcr.io/distroless/cc-debian12, which has no shell, no curl and no wget. A
// compose `healthcheck` therefore had nowhere to run, so neither container ever
// reported health to Docker — `docker ps` showed "Up" for a hung control plane,
// and `depends_on: condition: service_healthy` could not be used at all. Both
// binaries already serve a readiness endpoint; this gives Docker something that
// can call it.
//
// It is deliberately tiny and stdlib-only so it stays a static binary that can be
// copied into a distroless stage with no runtime dependencies:
//
//	healthprobe http://127.0.0.1:8080/readyz
//
// Exit 0 when the endpoint answers 2xx, 1 otherwise. Any non-2xx, a timeout, or a
// refused connection is a failure, which is what a healthcheck should treat as
// unhealthy.
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: healthprobe <url>")
		os.Exit(2)
	}
	url := os.Args[1]

	// Short timeout: Docker's own healthcheck timeout is the outer bound, and a
	// probe that hangs is indistinguishable from one that fails, so fail fast.
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthprobe: %s: %v\n", url, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		fmt.Fprintf(os.Stderr, "healthprobe: %s: HTTP %s\n", url, resp.Status)
		os.Exit(1)
	}
	os.Exit(0)
}
