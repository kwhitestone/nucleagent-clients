// Package catalog validates the signed, closed set of runtime installation inputs.
package catalog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"strings"
)

const Schema = 1

type Signed struct {
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}

type Catalog struct {
	Schema   int      `json:"schema"`
	Sequence uint64   `json:"sequence"`
	Revoked  []string `json:"revoked"`
	Bundles  []Bundle `json:"bundles"`
}

type Bundle struct {
	ID             string     `json:"id"`
	Backend        string     `json:"backend"`
	OS             string     `json:"os"`
	Arch           string     `json:"arch"`
	MinOS          string     `json:"minOS"`
	Version        string     `json:"version"`
	AdapterVersion string     `json:"adapterVersion"`
	Entry          string     `json:"entry"`
	Probe          []string   `json:"probe"`
	Artifacts      []Artifact `json:"artifacts"`
	Files          []File     `json:"files"`
}

type Artifact struct {
	StripPrefix  string   `json:"stripPrefix,omitempty"`
	Destination  string   `json:"destination,omitempty"`
	ID           string   `json:"id"`
	Version      string   `json:"version"`
	URL          string   `json:"url"`
	Bytes        int64    `json:"bytes"`
	SHA256       string   `json:"sha256"`
	Format       string   `json:"format"`
	Publisher    string   `json:"publisher"`
	Verification string   `json:"verification"`
	Dependencies []string `json:"dependencies"`
}

type File struct {
	Path       string `json:"path"`
	Bytes      int64  `json:"bytes"`
	SHA256     string `json:"sha256"`
	Executable bool   `json:"executable"`
}

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

// Relative accepts a conservative portable path, including on Windows.
// Reject ADS, device paths, reserved DOS names, traversal and case aliases.
func Relative(p string) bool {
	if p == "" || path.IsAbs(p) || path.Clean(p) != p || strings.ContainsAny(p, "\\:\x00") {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == "." || part == ".." || strings.TrimRight(part, " .") != part {
			return false
		}
		stem := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" || stem == "CONIN$" || stem == "CONOUT$" {
			return false
		}
		if len(stem) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) && strings.ContainsRune("123456789¹²³", rune(stem[3])) {
			return false
		}
		for _, r := range part {
			if r < 32 || strings.ContainsRune(`<>"|?*`, r) {
				return false
			}
		}
	}
	return true
}

func digest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == sha256.Size && s == strings.ToLower(s)
}

func Decode(raw []byte, key ed25519.PublicKey, minimumSequence uint64) (*Catalog, error) {
	if len(raw) > 8<<20 {
		return nil, errors.New("catalog too large")
	}
	var signed Signed
	if err := strict(raw, &signed); err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, signed.Payload, sig) {
		return nil, errors.New("catalog signature rejected")
	}
	var c Catalog
	if err := strict(signed.Payload, &c); err != nil {
		return nil, err
	}
	if c.Schema != Schema || c.Sequence == 0 || c.Sequence < minimumSequence || len(c.Bundles) == 0 {
		return nil, errors.New("catalog schema or sequence rejected")
	}
	ids := map[string]bool{}
	for _, b := range c.Bundles {
		if ids[b.ID] {
			return nil, errors.New("duplicate bundle")
		}
		ids[b.ID] = true
		if err := b.Validate(); err != nil {
			return nil, fmt.Errorf("bundle %s: %w", b.ID, err)
		}
	}
	for _, id := range c.Revoked {
		if !identifier.MatchString(id) {
			return nil, errors.New("invalid revocation")
		}
	}
	return &c, nil
}

func strict(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func (c *Catalog) Select(backend, platform, arch string) (Bundle, error) {
	for _, b := range c.Bundles {
		if b.Backend != backend || b.OS != platform || b.Arch != arch {
			continue
		}
		for _, id := range c.Revoked {
			if id == b.ID {
				return Bundle{}, errors.New("generation revoked")
			}
		}
		return b, nil
	}
	return Bundle{}, errors.New("unsupported backend or platform")
}

func (b Bundle) Validate() error {
	if !identifier.MatchString(b.ID) || (b.Backend != "codex" && b.Backend != "opencode") || b.Version == "" || b.AdapterVersion == "" || b.MinOS == "" || len(b.Probe) == 0 || !Relative(b.Entry) {
		return errors.New("missing bundle identity or probe")
	}
	if !(b.OS == "windows" && b.Arch == "amd64" || b.OS == "darwin" && b.Arch == "arm64") {
		return errors.New("platform outside P0")
	}
	if len(b.Artifacts) == 0 || len(b.Files) == 0 {
		return errors.New("empty dependency closure")
	}
	deps := map[string][]string{}
	for _, a := range b.Artifacts {
		if a.StripPrefix != "" && !Relative(a.StripPrefix) || a.Destination != "" && !Relative(a.Destination) {
			return errors.New("unsafe artifact mapping")
		}
		u, e := url.Parse(a.URL)
		if e != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Host != "github.com" && u.Host != "registry.npmjs.org" {
			return errors.New("artifact origin rejected")
		}
		if strings.Contains(u.Path, "/latest/") || !identifier.MatchString(a.ID) || a.Version == "" || strings.ContainsAny(a.Version, "^~*<>= ") || a.Bytes <= 0 || a.Bytes > 1<<30 || !digest(a.SHA256) || a.Publisher == "" || a.Verification != "sha256-and-signed-catalog" {
			return errors.New("unlocked artifact")
		}
		if a.Format != "tar.gz" && a.Format != "zip" {
			return errors.New("unsupported archive")
		}
		if _, ok := deps[a.ID]; ok {
			return errors.New("duplicate artifact")
		}
		deps[a.ID] = a.Dependencies
	}
	visited, visiting := map[string]bool{}, map[string]bool{}
	var visit func(string) error
	visit = func(id string) error {
		list, ok := deps[id]
		if !ok {
			return errors.New("dependency missing from closure")
		}
		if visiting[id] {
			return errors.New("dependency cycle")
		}
		if visited[id] {
			return nil
		}
		visiting[id] = true
		for _, d := range list {
			if err := visit(d); err != nil {
				return err
			}
		}
		delete(visiting, id)
		visited[id] = true
		return nil
	}
	for id := range deps {
		if err := visit(id); err != nil {
			return err
		}
	}
	files := map[string]bool{}
	entry := false
	var total int64
	for _, f := range b.Files {
		name := strings.ToLower(f.Path)
		if !Relative(f.Path) || files[name] || !digest(f.SHA256) || f.Bytes < 0 || f.Bytes > 1<<30 {
			return errors.New("invalid file closure")
		}
		files[name] = true
		total += f.Bytes
		if f.Path == b.Entry && f.Executable {
			entry = true
		}
	}
	if !entry || total > 4<<30 {
		return errors.New("entry missing or closure too large")
	}
	return nil
}
