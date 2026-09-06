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

// Product is the release version. Bump it together with VERSION, Cargo.toml
// [workspace.package].version and dashboard/package.json — CI refuses a drift.
const Product = "1.1.0"

// Commit is the git SHA the binary was built from; set via -ldflags.
var Commit = "unknown"

// BuildDate is the RFC 3339 build timestamp; set via -ldflags.
var BuildDate = "unknown"

// Info is the map every status endpoint embeds so operators see one version.
func Info() map[string]string {
	return map[string]string{
		"product_version": Product,
		"commit":          Commit,
		"build_date":      BuildDate,
	}
}
