package safego

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// unguarded lists, per file, how many `go` statements may start a goroutine
// with no panic containment, and why. Everything else in the control plane's
// own code must go through safego.Go / safego.Loop, or recover in the
// goroutine itself.
//
// Adding a background task? Use safego.Loop (it runs for the life of the
// process) or safego.Go (one-shot). Add to this list only with a reason that a
// reviewer would accept for taking the process down.
var unguarded = map[string]struct {
	n   int
	why string
}{
	"cmd/controllerd/main.go":     {2, "the REST server itself, and the dev-only local data-plane launcher"},
	"cmd/controllerd/shutdown.go": {1, "waits on pool.Close during exit"},
	"internal/leader/leader.go":   {1, "a panic in leader election must end the process (see Loop)"},
	"internal/logs/simulator.go":  {1, "dev-only fake traffic, off unless SENTINEL_DEV_SIMULATOR=1"},
	"internal/safego/safego.go":   {2, "Go and Loop: the guarded launchers themselves"},
}

// TestEveryBackgroundGoroutineIsGuarded walks the control plane's non-test
// source. It parses the code, so a `go func` in a comment or a string is not a
// finding and cannot hide one.
func TestEveryBackgroundGoroutineIsGuarded(t *testing.T) {
	root := filepath.Join("..", "..")
	found := map[string]int{}
	fset := token.NewFileSet()

	for _, dir := range []string{"cmd/controllerd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			ast.Inspect(file, func(n ast.Node) bool {
				g, ok := n.(*ast.GoStmt)
				if !ok {
					return true
				}
				if lit, ok := g.Call.Fun.(*ast.FuncLit); ok && recoversItself(lit) {
					return true
				}
				found[rel]++
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	var files []string
	for f := range found {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, f := range files {
		allowed := unguarded[f]
		if found[f] > allowed.n {
			t.Errorf("%s: %d unguarded `go` statement(s), %d allowed — start it with safego.Go or safego.Loop, "+
				"or defer safego.Recover inside it", f, found[f], allowed.n)
		}
	}
	for f, a := range unguarded {
		if found[f] < a.n {
			t.Errorf("%s: allowlist says %d unguarded goroutine(s) (%s) but only %d remain — lower the number",
				f, a.n, a.why, found[f])
		}
	}
}

// recoversItself reports whether a goroutine's body defers a recovery: a call
// into this package (Recover) or a closure that calls recover().
func recoversItself(lit *ast.FuncLit) bool {
	for _, stmt := range lit.Body.List {
		d, ok := stmt.(*ast.DeferStmt)
		if !ok {
			continue
		}
		if sel, ok := d.Call.Fun.(*ast.SelectorExpr); ok {
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "safego" && sel.Sel.Name == "Recover" {
				return true
			}
		}
		if inner, ok := d.Call.Fun.(*ast.FuncLit); ok {
			calls := false
			ast.Inspect(inner, func(n ast.Node) bool {
				if c, ok := n.(*ast.CallExpr); ok {
					if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "recover" {
						calls = true
					}
				}
				return !calls
			})
			if calls {
				return true
			}
		}
	}
	return false
}
