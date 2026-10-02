package release

import (
	"crypto/ed25519"
	"encoding/base64"
	"nucleagent-desktop-runner/internal/catalog"
	"strings"
	"testing"
)

func TestEmbeddedCatalogSignatureAndClosure(t *testing.T) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	c, err := catalog.Decode(Catalog, ed25519.PublicKey(key), 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, platform := range []struct{ os, arch string }{{"windows", "amd64"}, {"darwin", "arm64"}} {
		for _, backend := range []string{"codex", "opencode"} {
			b, err := c.Select(backend, platform.os, platform.arch)
			if err != nil {
				t.Fatal(err)
			}
			if backend == "opencode" && len(b.Artifacts) < 2 {
				t.Fatal("OpenCode transitive closure absent")
			}
		}
	}
}
