package adapter

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nucleagent/nucleagent-shared/a2a"
	"nucleagent-desktop-runner/internal/catalog"
	"nucleagent-desktop-runner/internal/platform"
)

// InstallSkills accepts only hash-pinned ZIP packages explicitly selected by
// Core. No redirects, links, executable install scripts or host configuration.
func InstallSkills(ctx context.Context, root string, bindings []a2a.SkillBindingView) error {
	if len(bindings) > 10 {
		return errors.New("too many skills")
	}
	client := &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	seen := map[string]bool{}
	for _, b := range bindings {
		if !catalog.Relative(b.Slug) || strings.Contains(b.Slug, "/") || seen[b.Slug] || len(b.SHA256) != 64 {
			return errors.New("invalid skill identity")
		}
		seen[b.Slug] = true
		u, err := url.Parse(b.DownloadURL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
			return errors.New("invalid skill download URL")
		}
		req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
		if err != nil {
			return errors.New("invalid skill request")
		}
		res, err := client.Do(req)
		if err != nil {
			return errors.New("skill download unavailable")
		}
		data, readErr := io.ReadAll(io.LimitReader(res.Body, (20<<20)+1))
		_ = res.Body.Close()
		if readErr != nil || res.StatusCode != 200 || len(data) > 20<<20 {
			return errors.New("skill download failed")
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != strings.ToLower(b.SHA256) {
			return errors.New("skill package checksum mismatch")
		}
		if err := extractSkill(filepath.Join(root, "workspace", ".agents", "skills", b.Slug), data); err != nil {
			return err
		}
	}
	return nil
}

func extractSkill(destination string, data []byte) error {
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil || len(archive.File) > 512 {
		return errors.New("invalid skill archive")
	}
	// SkillHub packages may wrap all entries in the exact selected slug.
	// Preserve the ZIP checksum and strip only that one verified directory.
	prefix := filepath.Base(destination) + "/"
	for _, file := range archive.File {
		if file.Name == "SKILL.md" {
			prefix = ""
			break
		}
	}
	seen := map[string]bool{}
	var total uint64
	found := false
	for _, file := range archive.File {
		name := strings.TrimSuffix(file.Name, "/")
		if !catalog.Relative(name) || file.Mode()&os.ModeSymlink != 0 || !file.Mode().IsRegular() && !file.FileInfo().IsDir() || seen[strings.ToLower(name)] {
			return errors.New("unsafe skill entry")
		}
		if prefix != "" {
			if file.FileInfo().IsDir() && name == strings.TrimSuffix(prefix, "/") {
				continue
			}
			if !strings.HasPrefix(name, prefix) {
				return errors.New("skill archive has an unexpected root")
			}
			name = strings.TrimPrefix(name, prefix)
			if !catalog.Relative(name) || seen[strings.ToLower(name)] {
				return errors.New("unsafe skill entry")
			}
		}
		seen[strings.ToLower(name)] = true
		total += file.UncompressedSize64
		if total > 50<<20 {
			return errors.New("skill extraction exceeds limit")
		}
		path := filepath.Join(destination, filepath.FromSlash(name))
		if file.FileInfo().IsDir() {
			if err := platform.PrivateDirectory(path); err != nil {
				return err
			}
			continue
		}
		if err := platform.PrivateDirectory(filepath.Dir(path)); err != nil {
			return err
		}
		r, err := file.Open()
		if err != nil {
			return errors.New("skill entry unavailable")
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			r.Close()
			return errors.New("skill path unavailable")
		}
		n, copyErr := io.Copy(f, io.LimitReader(r, (50<<20)+1))
		closeErr := errors.Join(f.Close(), r.Close())
		if copyErr != nil || closeErr != nil || uint64(n) != file.UncompressedSize64 {
			return errors.New("skill extraction incomplete")
		}
		if name == "SKILL.md" {
			found = true
		}
	}
	if !found {
		return errors.New("skill archive has no root SKILL.md")
	}
	return nil
}
