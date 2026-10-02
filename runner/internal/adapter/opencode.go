package adapter

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"nucleagent-desktop-runner/internal/catalog"
	"nucleagent-desktop-runner/internal/platform"
)

//go:embed opencode-package-lock.json
var opencodeLock []byte

// The native package embeds Bun and the configured provider SDK. No npm
// installation is performed; the exact plugin tree is materialized from the
// signed generation. All optional native package variants are also locked.
func prepareOpenCode(root, generation string, b catalog.Bundle) error {
	target := filepath.Join(root, "config", "opencode")
	if err := platform.PrivateDirectory(target); err != nil {
		return err
	}
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	if json.Unmarshal(opencodeLock, &lock) != nil || lock.Packages["node_modules/@opencode-ai/plugin"].Version != b.Version {
		return errors.New("OpenCode dependency lock version mismatch")
	}
	for _, f := range b.Files {
		if !strings.HasPrefix(f.Path, "dependencies/node_modules/") {
			continue
		}
		rel := strings.TrimPrefix(f.Path, "dependencies/")
		dest := filepath.Join(target, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			return err
		}
		src, err := os.Open(filepath.Join(generation, filepath.FromSlash(f.Path)))
		if err != nil {
			return err
		}
		perm := os.FileMode(0600)
		if f.Executable {
			perm = 0700
		}
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
		if err != nil {
			src.Close()
			return err
		}
		h := sha256.New()
		n, copyErr := io.Copy(io.MultiWriter(out, h), io.LimitReader(src, f.Bytes+1))
		err = errors.Join(copyErr, src.Close(), out.Close())
		if err != nil {
			return err
		}
		if n != f.Bytes || hex.EncodeToString(h.Sum(nil)) != f.SHA256 {
			return errors.New("OpenCode dependency copy integrity rejected")
		}
	}
	if _, err := os.Stat(filepath.Join(target, "node_modules", "@opencode-ai", "plugin", "package.json")); err != nil {
		return errors.New("OpenCode plugin closure missing")
	}
	for name, data := range map[string][]byte{"package-lock.json": opencodeLock, "package.json": []byte(`{"private":true,"dependencies":{"@opencode-ai/plugin":"` + b.Version + `"}}`)} {
		if err := os.WriteFile(filepath.Join(target, name), data, 0600); err != nil {
			return err
		}
	}
	return nil
}

func verifyOpenCodeClosure(root string, b catalog.Bundle) error {
	var mapped catalog.Bundle
	for _, f := range b.Files {
		if strings.HasPrefix(f.Path, "dependencies/node_modules/") {
			f.Path = strings.TrimPrefix(f.Path, "dependencies/node_modules/")
			mapped.Files = append(mapped.Files, f)
		}
	}
	if len(mapped.Files) == 0 {
		return errors.New("OpenCode plugin closure missing")
	}
	if err := catalog.Verify(filepath.Join(root, "config", "opencode", "node_modules"), mapped); err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(root, "config", "opencode", "package-lock.json"))
	if err != nil || !bytes.Equal(data, opencodeLock) {
		return errors.New("OpenCode dependency lock drift")
	}
	return nil
}

func probeOpenCode(ctx context.Context, generation string, b catalog.Bundle) (err error) {
	root, err := os.MkdirTemp(filepath.Dir(generation), "probe-opencode-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	env, err := platform.Environment(root, []string{generation})
	if err != nil {
		return err
	}
	if err = prepareOpenCode(root, generation, b); err != nil {
		return err
	}
	// This probe never loads a real model or sends a prompt. Unknown tools,
	// plugins, LSP/formatter downloads, remote model fetches and updates are off.
	config := map[string]any{"$schema": "https://opencode.ai/config.json", "autoupdate": false, "share": "disabled", "plugin": []any{}, "mcp": map[string]any{}, "lsp": false, "formatter": false, "permission": map[string]string{"*": "deny"}, "enabled_providers": []string{}, "agent": map[string]any{"explore": map[string]bool{"disable": true}}}
	raw, _ := json.Marshal(config)
	password := make([]byte, 32)
	if _, err = rand.Read(password); err != nil {
		return err
	}
	token := hex.EncodeToString(password)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err = listener.Close(); err != nil {
		return err
	}
	env = append(env, "OPENCODE_CONFIG_CONTENT="+string(raw), "OPENCODE_DISABLE_PROJECT_CONFIG=1", "OPENCODE_DISABLE_AUTOUPDATE=1", "OPENCODE_DISABLE_MODELS_FETCH=1", "OPENCODE_DISABLE_FFF=1", "OPENCODE_EXPERIMENTAL_DISABLE_FILEWATCHER=1", "OPENCODE_SERVER_USERNAME=nucleagent", "OPENCODE_SERVER_PASSWORD="+token)
	p, err := platform.Start(platform.Spec{Executable: filepath.Join(generation, b.Entry), Args: []string{"serve", "--hostname", "127.0.0.1", "--port", strconv.Itoa(port)}, Env: env, Directory: filepath.Join(root, "workspace")})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, p.Close(), verifyOpenCodeClosure(root, b)) }()
	go func() { _, _ = io.Copy(io.Discard, p.Stderr) }()
	go func() { _, _ = io.Copy(io.Discard, p.Stdout) }()
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	endpoint := "http://127.0.0.1:" + strconv.Itoa(port)
	call := func(method, path string, body []byte) ([]byte, error) {
		req, e := http.NewRequestWithContext(ctx, method, endpoint+path+"?directory="+url.QueryEscape(filepath.Join(root, "workspace")), bytes.NewReader(body))
		if e != nil {
			return nil, e
		}
		req.SetBasicAuth("nucleagent", token)
		req.Header.Set("Content-Type", "application/json")
		res, e := client.Do(req)
		if e != nil {
			return nil, errors.New("OpenCode control request failed")
		}
		defer res.Body.Close()
		data, e := io.ReadAll(io.LimitReader(res.Body, 1<<20+1))
		if e != nil {
			return nil, e
		}
		if len(data) > 1<<20 || res.StatusCode < 200 || res.StatusCode >= 300 {
			return nil, errors.New("OpenCode control response rejected")
		}
		return data, nil
	}
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		data, e := call("GET", "/global/health", nil)
		var health struct {
			Healthy bool   `json:"healthy"`
			Version string `json:"version"`
		}
		if e == nil && json.Unmarshal(data, &health) == nil && health.Healthy && health.Version == b.Version {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return errors.New("OpenCode protocol readiness timed out")
		case <-p.Done():
			return errors.New("OpenCode exited before readiness")
		case <-ticker.C:
		}
	}
	data, err := call("POST", "/session", []byte(`{}`))
	if err != nil {
		return err
	}
	var session struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(data, &session) != nil || session.ID == "" || strings.ContainsAny(session.ID, "/?#") {
		return errors.New("OpenCode returned invalid session identity")
	}
	_, err = call("DELETE", "/session/"+url.PathEscape(session.ID), nil)
	return err
}
