package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// Every handler that rewrites a site must record an undo point first.
//
// config_versions.go says snapshots are "taken on every config mutation", and the
// console's Config history offers them as rollback points. Until 2026-10-19 only
// site update, delete, import and rollback took one: blocking a country (which
// rewrites EVERY site's policy), pausing a site and adding or removing a rule
// exclusion changed live config with no way back from the history page.
//
// This parses the package and fails on any function that calls a site-mutating
// store method without calling snapshotBeforeMutation, so the next handler added
// cannot quietly skip it.
func TestEverySiteMutationTakesAnUndoPoint(t *testing.T) {
	mutators := map[string]bool{"UpdateSite": true, "UpdateSiteStatus": true, "DeleteSite": true}
	// Functions that may call a mutator without their own snapshot, with why.
	exempt := map[string]string{
		// The rollback snapshots in its handler before calling the store.
		"handleRollbackConfigVersion": "snapshots before RestoreConfigVersion",
	}

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var offenders []string
	scanned := 0
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, n, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", n, err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			scanned++
			mutates, snapshots := false, false
			ast.Inspect(fd.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fn := call.Fun.(type) {
				case *ast.SelectorExpr:
					if x, ok := fn.X.(*ast.Ident); ok && x.Name == "store" && mutators[fn.Sel.Name] {
						mutates = true
					}
				case *ast.Ident:
					if fn.Name == "snapshotBeforeMutation" {
						snapshots = true
					}
				}
				return true
			})
			if mutates && !snapshots {
				if _, ok := exempt[fd.Name.Name]; !ok {
					offenders = append(offenders, n+": "+fd.Name.Name)
				}
			}
		}
	}
	if scanned < 50 {
		t.Fatalf("scanned only %d functions — the guard is not reading the package", scanned)
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Errorf("site mutations with no undo point (call snapshotBeforeMutation first):\n  %s",
			strings.Join(offenders, "\n  "))
	}
}
