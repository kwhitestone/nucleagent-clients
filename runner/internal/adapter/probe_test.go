package adapter_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	release "nucleagent-desktop-runner/catalog"
	"nucleagent-desktop-runner/internal/adapter"
	"nucleagent-desktop-runner/internal/catalog"
)

// Explicit opt-in for a downloaded Linux binary used ONLY to exercise the
// protocol. This cannot turn a Linux node into a supported PC execution target.
func TestWSLOpenCodeProtocolFixture(t *testing.T) {
	dir := os.Getenv("G9_LINUX_PROTOCOL_FIXTURE")
	if dir == "" {
		t.Skip("requires explicitly downloaded, hash-verified Linux fixture")
	}
	if !filepath.IsAbs(dir) {
		t.Fatal("absolute fixture directory required")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(release.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	c, err := catalog.Decode(release.Catalog, ed25519.PublicKey(key), 2)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Select("opencode", "windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	b.Entry = "opencode" // Native Linux executable, not Windows or macOS evidence.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err = adapter.Version(ctx, dir, b); err != nil {
		t.Fatal(err)
	}
	if err = adapter.Probe(ctx, dir, b); err != nil {
		t.Fatal(err)
	}
}

func TestWSLCodexProtocolFixture(t *testing.T) {
	dir := os.Getenv("G9_CODEX_PROTOCOL_FIXTURE")
	if dir == "" {
		t.Skip("requires explicitly downloaded, hash-verified Codex fixture")
	}
	if !filepath.IsAbs(dir) {
		t.Fatal("absolute fixture directory required")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(release.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	c, err := catalog.Decode(release.Catalog, ed25519.PublicKey(key), 2)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Select("codex", "darwin", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err = adapter.Version(ctx, dir, b); err != nil {
		t.Fatal(err)
	}
	if err = adapter.Probe(ctx, dir, b); err != nil {
		t.Fatal(err)
	}
}
