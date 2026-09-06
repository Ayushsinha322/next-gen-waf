package geoipfetch

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExpandURL(t *testing.T) {
	got := ExpandURL(DefaultURL, time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC))
	if got != "https://download.db-ip.com/free/dbip-country-lite-2026-09.mmdb.gz" {
		t.Fatalf("got %s", got)
	}
}

func TestValidateMMDBRejectsHTMLAndAcceptsMarker(t *testing.T) {
	dir := t.TempDir()
	html := filepath.Join(dir, "captive.mmdb")
	os.WriteFile(html, []byte("<html>"+string(make([]byte, 4096))+"</html>"), 0o644)
	if err := ValidateMMDB(html); err == nil {
		t.Fatal("an HTML page must not validate as a database")
	}
	ok := filepath.Join(dir, "ok.mmdb")
	body := append(make([]byte, 4096), []byte("\xab\xcd\xefMaxMind.com{binary metadata}")...)
	os.WriteFile(ok, body, 0o644)
	if err := ValidateMMDB(ok); err != nil {
		t.Fatalf("marker present must validate: %v", err)
	}
	small := filepath.Join(dir, "small.mmdb")
	os.WriteFile(small, []byte("\xab\xcd\xefMaxMind.com"), 0o644)
	if err := ValidateMMDB(small); err == nil {
		t.Fatal("a tiny file must be rejected")
	}
}
