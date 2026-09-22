// Package version is the single place the control plane knows what it is.
//
// Product is pinned to the repo-root VERSION file by
// deploy/ci/check-version-consistency.sh, alongside Cargo.toml and
// dashboard/package.json, so every component reports the same number. Commit
// and BuildDate are injected at build time with
//
//	-ldflags "-X .../internal/version.Commit=$GIT_SHA -X .../internal/version.BuildDate=$BUILD_DATE"
//
// and stay "unknown" in a plain `go build`.
package version

import (
	"os"
	"strings"
)

// Name is what the product is CALLED, as a customer reads it.
//
// `sentinel` is the codename for this source tree — the module path, the
// binaries, the env prefix, the image tags. It is not the product name. Nor is
// "Next-Gen ESDSWAF", which this name replaced and which was still going out in
// every password-reset email.
//
// This matters most where the string is durable or leaves the building: the
// TOTP issuer lands in an administrator's authenticator app and stays there for
// the life of the account, and mail and alert payloads are read by people who
// never see the console. The console enforces the same rule in
// dashboard/lib/__tests__/branding.test.ts.
const Name = "Swaraj Kavach"

// Product is the release version. Bump it together with VERSION, Cargo.toml
// [workspace.package].version and dashboard/package.json — CI refuses a drift.
const Product = "1.1.4"

// CommitLinked and BuildDateLinked are what the binary was built from, injected
// by the Dockerfile with
//
//	-X .../internal/version.CommitLinked=$GIT_SHA
//
// Read them through Commit() and BuildDate(), which prefer the deployment's own
// value.
//
// EXPORTED on purpose. They were briefly unexported, and `go build -X` on a
// symbol it cannot find is a SILENT no-op — so the injection stopped working and
// every binary reported "unknown" while the build logs looked perfect. The names
// here and in the Dockerfile are now checked against each other by
// deploy/ci/check-version-consistency.sh.
var (
	CommitLinked    = "unknown"
	BuildDateLinked = "unknown"
)

// Commit is the git SHA this deployment is running.
//
// Link-time only was wrong. A deploy that changes one component retags the
// other images so a single SENTINEL_VERSION names a consistent set — the images
// are byte-identical, so rebuilding them would be waste — but their link-time
// SHA then belongs to the PREVIOUS version, and the console reported that older
// commit while the deployed set was newer. Observed on 2026-09-07: the console
// said 7076e7f for two deploys while ac1b911 was live.
//
// SENTINEL_GIT_SHA, which compose already sets from the same .env value that
// picks the image tags, is therefore authoritative when present. The link-time
// value remains the fallback for a plain `go build` or a bare `docker run`.
func Commit() string {
	if v := strings.TrimSpace(os.Getenv("SENTINEL_GIT_SHA")); v != "" && v != "unknown" {
		return v
	}
	return CommitLinked
}

// BuildDate is the RFC 3339 timestamp of the deployed set, same reasoning.
func BuildDate() string {
	if v := strings.TrimSpace(os.Getenv("SENTINEL_BUILD_DATE")); v != "" && v != "unknown" {
		return v
	}
	return BuildDateLinked
}

// LinkedCommit reports what THIS binary was compiled from, regardless of the
// environment — so "the image is a retag of an older build" stays diagnosable
// instead of being papered over by the value above.
func LinkedCommit() string { return CommitLinked }

// Info is the map every status endpoint embeds so operators see one version.
func Info() map[string]string {
	out := map[string]string{
		"product_version": Product,
		"commit":          Commit(),
		"build_date":      BuildDate(),
	}
	// Only stated when they differ, which is exactly the retag case.
	if lc := LinkedCommit(); lc != out["commit"] {
		out["binary_built_from"] = lc
	}
	return out
}
