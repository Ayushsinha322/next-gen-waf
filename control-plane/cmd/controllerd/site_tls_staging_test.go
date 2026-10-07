package main

import (
	"encoding/json"
	"testing"
)

func TestTheConsolesStagingSwitchSelectsTheStagingCA(t *testing.T) {
	tls := buildRustSiteTLS(json.RawMessage(`{"tls":{"mode":"auto","email":"ops@example.in","provider":"letsencrypt","staging":true}}`))
	acme, _ := tls["acme"].(map[string]any)
	if acme["provider"] != "lets_encrypt_staging" {
		t.Fatalf("staging was ignored: %v", tls)
	}
	prod := buildRustSiteTLS(json.RawMessage(`{"tls":{"mode":"auto","email":"ops@example.in","provider":"letsencrypt"}}`))
	if p, _ := prod["acme"].(map[string]any); p["provider"] != "lets_encrypt" {
		t.Fatalf("production orders must stay on production: %v", prod)
	}
}
