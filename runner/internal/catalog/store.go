package catalog

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Progress struct {
	State    string `json:"state"`
	Artifact string `json:"artifact,omitempty"`
	Current  int64  `json:"current"`
	Total    int64  `json:"total"`
}

// Store installs immutable generations. Admission belongs to the caller and
// must remain closed until Install's protocol probe and Verify both succeed.
type Store struct {
	Directory string
	Client    *http.Client
	mu        sync.Mutex
}

func NewStore(directory string) *Store {
	return &Store{Directory: directory, Client: &http.Client{Timeout: 20 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || req.URL.Scheme != "https" || req.URL.User != nil {
			return errors.New("download redirect rejected")
		}
		h := req.URL.Hostname()
		if h != "github.com" && h != "release-assets.githubusercontent.com" && h != "objects.githubusercontent.com" && h != "registry.npmjs.org" {
			return errors.New("download redirect origin rejected")
		}
		return nil
	}}}
}

func (s *Store) Generation(b Bundle) string { return filepath.Join(s.Directory, "generations", b.ID) }

// Install never mutates a published generation. Failed probes leave no ready
// generation. The previous generation remains available for verified rollback.
func (s *Store) Install(ctx context.Context, b Bundle, report func(Progress), probe func(context.Context, string, Bundle) error) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := b.Validate(); err != nil {
		return "", err
	}
	if probe == nil {
		return "", errors.New("protocol probe required")
	}
	if !filepath.IsAbs(s.Directory) {
		return "", errors.New("absolute application directory required")
	}
	for _, d := range []string{s.Directory, filepath.Join(s.Directory, "staging"), filepath.Join(s.Directory, "downloads"), filepath.Join(s.Directory, "generations")} {
		if err := os.MkdirAll(d, 0700); err != nil {
			return "", err
		}
		info, err := os.Lstat(d)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("unsafe application directory")
		}
	}
	final := s.Generation(b)
	if _, err := os.Lstat(final); err == nil {
		if err := Verify(final, b); err != nil {
			return "", err
		}
		if err := probe(ctx, final, b); err != nil {
			return "", err
		}
		return final, Verify(final, b)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	stage, err := os.MkdirTemp(filepath.Join(s.Directory, "staging"), b.ID+"-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(stage)
	if report == nil {
		report = func(Progress) {}
	}
	expected := map[string]File{}
	for _, f := range b.Files {
		expected[f.Path] = f
	}
	seen := map[string]bool{}
	for _, a := range b.Artifacts {
		archive, err := s.download(ctx, a, report)
		if err != nil {
			return "", err
		}
		report(Progress{State: "installing", Artifact: a.ID})
		if err := extractMapped(archive, stage, a.Format, a.StripPrefix, a.Destination, expected, seen); err != nil {
			return "", err
		}
	}
	if err := Verify(stage, b); err != nil {
		return "", err
	}
	report(Progress{State: "probing"})
	if err := probe(ctx, stage, b); err != nil {
		return "", err
	}
	if err := Verify(stage, b); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := os.Rename(stage, final); err != nil {
		return "", err
	}
	report(Progress{State: "ready"})
	return final, nil
}

func (s *Store) download(ctx context.Context, a Artifact, report func(Progress)) (string, error) {
	filename := filepath.Join(s.Directory, "downloads", a.SHA256)
	if info, err := os.Lstat(filename); err == nil {
		if !info.Mode().IsRegular() {
			return "", errors.New("unsafe cache file")
		}
		if err := checkFile(filename, a.Bytes, a.SHA256); err == nil {
			return filename, nil
		}
		if err := os.Remove(filename); err != nil {
			return "", err
		}
	}
	f, err := os.CreateTemp(filepath.Join(s.Directory, "downloads"), "partial-")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept-Encoding", "identity")
	res, err := s.Client.Do(req)
	if err != nil {
		return "", errors.New("artifact download transport failed")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK || (res.ContentLength >= 0 && res.ContentLength != a.Bytes) {
		return "", errors.New("artifact HTTP status or byte length rejected")
	}
	h := sha256.New()
	writer := &progressWriter{w: io.MultiWriter(f, h), report: report, total: a.Bytes, id: a.ID}
	n, err := io.Copy(writer, io.LimitReader(res.Body, a.Bytes+1))
	if err != nil {
		return "", err
	}
	report(Progress{State: "verifying", Artifact: a.ID, Current: n, Total: a.Bytes})
	if n != a.Bytes || hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
		return "", errors.New("artifact integrity rejected")
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(f.Name(), filename); err != nil {
		return "", err
	}
	return filename, nil
}

type progressWriter struct {
	w              io.Writer
	report         func(Progress)
	total, current int64
	id             string
	last           time.Time
}

func (p *progressWriter) Write(b []byte) (int, error) {
	n, e := p.w.Write(b)
	p.current += int64(n)
	if time.Since(p.last) > 200*time.Millisecond || p.current >= p.total {
		p.report(Progress{State: "downloading", Artifact: p.id, Current: p.current, Total: p.total})
		p.last = time.Now()
	}
	return n, e
}

func extract(filename, destination, format string, expected map[string]File, seen map[string]bool) error {
	return extractMapped(filename, destination, format, "", "", expected, seen)
}

func extractMapped(filename, destination, format, strip, prefix string, expected map[string]File, seen map[string]bool) error {
	root, err := os.OpenRoot(destination)
	if err != nil {
		return err
	}
	defer root.Close()
	write := func(name string, size int64, mode fs.FileMode, r io.Reader) error {
		name = strings.TrimSuffix(name, "/")
		if !Relative(name) || mode&os.ModeSymlink != 0 {
			return errors.New("unsafe archive path or link")
		}
		if strip != "" {
			if name == strip && mode.IsDir() {
				return nil
			}
			if !strings.HasPrefix(name, strip+"/") {
				return errors.New("archive prefix mismatch")
			}
			name = strings.TrimPrefix(name, strip+"/")
		}
		if prefix != "" {
			name = prefix + "/" + name
		}
		if !Relative(name) {
			return errors.New("unsafe mapped archive path")
		}
		if mode.IsDir() {
			return root.MkdirAll(filepath.FromSlash(name), 0700)
		}
		if !mode.IsRegular() {
			return errors.New("archive special file rejected")
		}
		f, ok := expected[name]
		if !ok || seen[name] || f.Bytes != size {
			return errors.New("archive differs from signed file closure")
		}
		if err := root.MkdirAll(filepath.FromSlash(path.Dir(name)), 0700); err != nil {
			return err
		}
		perm := fs.FileMode(0600)
		if f.Executable {
			perm = 0700
		}
		out, err := root.OpenFile(filepath.FromSlash(name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
		if err != nil {
			return err
		}
		h := sha256.New()
		n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(r, size+1))
		syncErr := out.Sync()
		closeErr := out.Close()
		if err != nil {
			return err
		}
		if syncErr != nil {
			return syncErr
		}
		if closeErr != nil {
			return closeErr
		}
		if n != size || hex.EncodeToString(h.Sum(nil)) != f.SHA256 {
			return errors.New("unpacked file integrity rejected")
		}
		seen[name] = true
		return nil
	}
	if format == "zip" {
		z, err := zip.OpenReader(filename)
		if err != nil {
			return err
		}
		defer z.Close()
		for _, f := range z.File {
			if f.UncompressedSize64 > 1<<30 {
				return errors.New("archive file too large")
			}
			r, err := f.Open()
			if err != nil {
				return err
			}
			err = write(f.Name, int64(f.UncompressedSize64), f.Mode(), r)
			r.Close()
			if err != nil {
				return err
			}
		}
		return nil
	}
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	g, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer g.Close()
	t := tar.NewReader(g)
	for {
		h, err := t.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA && h.Typeflag != tar.TypeDir {
			return errors.New("archive link or special entry rejected")
		}
		if err := write(h.Name, h.Size, h.FileInfo().Mode(), t); err != nil {
			return err
		}
	}
}

func checkFile(filename string, size int64, digest string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, size+1))
	if err != nil {
		return err
	}
	if n != size || hex.EncodeToString(h.Sum(nil)) != digest {
		return errors.New("generation integrity drift")
	}
	return nil
}

// Verify must run immediately before a worker and after its entire process tree
// exits. A failure closes admission. It does not claim same-user sandboxing.
func Verify(directory string, b Bundle) error {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("unsafe generation directory")
	}
	expected := map[string]File{}
	for _, f := range b.Files {
		expected[f.Path] = f
	}
	count := 0
	err = filepath.WalkDir(directory, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if p == directory {
			return nil
		}
		rel, err := filepath.Rel(directory, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("generation link drift")
		}
		if d.IsDir() {
			return nil
		}
		f, ok := expected[rel]
		if !ok || !d.Type().IsRegular() {
			return errors.New("unexpected generation file")
		}
		if err := checkFile(p, f.Bytes, f.SHA256); err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		count++
		return nil
	})
	if err != nil {
		return err
	}
	if count != len(expected) {
		return errors.New("missing generation file")
	}
	return nil
}
