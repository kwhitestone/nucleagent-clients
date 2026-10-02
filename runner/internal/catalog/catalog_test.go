package catalog

import (
	"archive/zip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sum(b []byte) string { d := sha256.Sum256(b); return hex.EncodeToString(d[:]) }
func fixture() Bundle {
	return Bundle{ID: "codex-1-windows-amd64", Backend: "codex", OS: "windows", Arch: "amd64", MinOS: "10.0.26100", Version: "1", AdapterVersion: "1", Entry: "bin/codex.exe", Probe: []string{"app-server"}, Artifacts: []Artifact{{ID: "native", Version: "1", URL: "https://github.com/openai/codex/releases/download/fixed/native.zip", Bytes: 3, SHA256: sum([]byte("zip")), Format: "zip", Publisher: "openai", Verification: "sha256-and-signed-catalog"}}, Files: []File{{Path: "bin/codex.exe", Bytes: 3, SHA256: sum([]byte("exe")), Executable: true}}}
}

func TestSignedCatalogFailsClosed(t *testing.T) {
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	payload, _ := json.Marshal(Catalog{Schema: Schema, Sequence: 2, Bundles: []Bundle{fixture()}})
	s := Signed{Payload: payload, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload))}
	raw, _ := json.Marshal(s)
	if _, e := Decode(raw, pub, 2); e != nil {
		t.Fatal(e)
	}
	if _, e := Decode(raw, pub, 3); e == nil {
		t.Fatal("rollback accepted")
	}
	s.Payload = []byte(strings.Replace(string(payload), `"sequence":2`, `"sequence":3`, 1))
	raw, _ = json.Marshal(s)
	if _, e := Decode(raw, pub, 2); e == nil {
		t.Fatal("tampered catalog accepted")
	}
}

func TestClosureAndPortablePaths(t *testing.T) {
	for _, p := range []string{"../outside", "/outside", "C:/outside", "foo\\bar", "file:ads", "CON.txt", "x/NUL", "x/LPT1.log", "space ", "x/../y", "x//y"} {
		if Relative(p) {
			t.Errorf("accepted %q", p)
		}
	}
	for _, mutate := range []func(*Bundle){
		func(b *Bundle) { b.Artifacts[0].Dependencies = []string{"missing"} },
		func(b *Bundle) { b.Artifacts[0].Dependencies = []string{"native"} },
		func(b *Bundle) { b.Artifacts[0].Version = "^1.0.0" },
		func(b *Bundle) { b.Artifacts[0].SHA256 = "placeholder" },
		func(b *Bundle) { b.Artifacts[0].URL = "http://github.com/package" },
		func(b *Bundle) { b.Artifacts[0].URL = "https://github.com/releases/latest/native.zip" },
		func(b *Bundle) { b.Files = append(b.Files, File{Path: "BIN/CODEX.EXE", SHA256: sum(nil)}) },
		func(b *Bundle) { b.Files = nil },
	} {
		b := fixture()
		mutate(&b)
		if b.Validate() == nil {
			t.Errorf("invalid closure accepted: %+v", b)
		}
	}
}

func TestExtractRejectsTraversalAndLinks(t *testing.T) {
	for _, name := range []string{"../escape", "bin/codex.exe"} {
		t.Run(name, func(t *testing.T) {
			file, err := os.CreateTemp(t.TempDir(), "archive")
			if err != nil {
				t.Fatal(err)
			}
			z := zip.NewWriter(file)
			hdr := &zip.FileHeader{Name: name}
			if name == "bin/codex.exe" {
				hdr.SetMode(os.ModeSymlink | 0777)
			}
			w, _ := z.CreateHeader(hdr)
			w.Write([]byte("exe"))
			z.Close()
			file.Close()
			b := fixture()
			if e := extract(file.Name(), t.TempDir(), "zip", map[string]File{b.Entry: b.Files[0]}, map[string]bool{}); e == nil {
				t.Fatal("unsafe archive extracted")
			}
		})
	}
}

func TestInstallProbeAndDrift(t *testing.T) {
	b := fixture()
	archive, err := os.CreateTemp(t.TempDir(), "asset.zip")
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(archive)
	w, _ := z.Create(b.Entry)
	w.Write([]byte("exe"))
	z.Close()
	archive.Close()
	data, _ := os.ReadFile(archive.Name())
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(data) }))
	defer srv.Close()
	b.Artifacts[0].Bytes = int64(len(data))
	b.Artifacts[0].SHA256 = sum(data)
	s := NewStore(t.TempDir())
	s.Client = srv.Client()
	// Rewrite only transport in this fixture; public manifest validation keeps
	// the production allowlist intact.
	s.Client.Transport = rewriteTransport{base: srv.Client().Transport, url: srv.URL}
	called := false
	probe := func(_ context.Context, dir string, b Bundle) error { called = true; return Verify(dir, b) }
	dir, err := s.Install(context.Background(), b, nil, probe)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("probe skipped")
	}
	if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(b.Entry)), []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	if Verify(dir, b) == nil {
		t.Fatal("drift accepted")
	}
	if _, err := s.Install(context.Background(), b, nil, probe); err == nil {
		t.Fatal("drifted generation reused")
	}
}

type rewriteTransport struct {
	base http.RoundTripper
	url  string
}

func (r rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	x := req.Clone(req.Context())
	u, _ := http.NewRequest(http.MethodGet, r.url, nil)
	x.URL = u.URL
	return r.base.RoundTrip(x)
}

func TestCorruptArchiveNeverProbesOrPublishes(t *testing.T) {
	b := fixture()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("bad")) }))
	defer srv.Close()
	s := NewStore(t.TempDir())
	s.Client = srv.Client()
	s.Client.Transport = rewriteTransport{base: srv.Client().Transport, url: srv.URL}
	_, err := s.Install(context.Background(), b, nil, func(context.Context, string, Bundle) error { t.Fatal("corrupt archive probed"); return nil })
	if err == nil {
		t.Fatal("corrupt archive accepted")
	}
	if _, e := os.Stat(s.Generation(b)); !os.IsNotExist(e) {
		t.Fatal("corrupt generation published")
	}
}

func TestMappedArchiveRejectsPrefixEscape(t *testing.T) {
	for _, test := range []struct {
		name string
		want bool
	}{{"package/index.js", true}, {"other/index.js", false}, {"package/../index.js", false}} {
		t.Run(test.name, func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "fixture.zip")
			file, err := os.Create(filename)
			if err != nil {
				t.Fatal(err)
			}
			archive := zip.NewWriter(file)
			entry, err := archive.Create(test.name)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = entry.Write([]byte("locked"))
			_ = archive.Close()
			_ = file.Close()
			name := "dependencies/node_modules/fixture/index.js"
			expected := map[string]File{name: {Path: name, Bytes: 6, SHA256: sum([]byte("locked"))}}
			err = extractMapped(filename, t.TempDir(), "zip", "package", "dependencies/node_modules/fixture", expected, map[string]bool{})
			if (err == nil) != test.want {
				t.Fatalf("mapping acceptance=%v expected=%v", err == nil, test.want)
			}
		})
	}
}
