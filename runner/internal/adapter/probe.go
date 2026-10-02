package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nucleagent-desktop-runner/internal/catalog"
	"nucleagent-desktop-runner/internal/platform"
)

// Probe initializes and closes an empty session. It never submits a prompt.
// Upstream inference is deliberately replaced with a loopback rejecting server.
func Probe(ctx context.Context, generation string, b catalog.Bundle) (err error) {
	if b.Backend == "opencode" {
		return probeOpenCode(ctx, generation, b)
	}
	if b.Backend != "codex" {
		return errors.New("unsupported backend")
	}
	root, err := os.MkdirTemp(filepath.Dir(generation), "probe-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	env, err := platform.Environment(root, []string{filepath.Dir(filepath.Join(generation, b.Entry))})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "inference disabled during probe", http.StatusForbidden)
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	endpoint := "http://" + listener.Addr().String() + "/v1"
	args := []string{"app-server", "--listen", "stdio://", "-c", `model_provider="nucleagent_probe"`, "-c", `model_providers.nucleagent_probe.name="NucleAgent probe"`, "-c", `model_providers.nucleagent_probe.base_url="` + endpoint + `"`, "-c", `model_providers.nucleagent_probe.wire_api="responses"`, "-c", `model_providers.nucleagent_probe.requires_openai_auth=false`, "-c", `model_providers.nucleagent_probe.env_key="NUCLEAGENT_LOOPBACK_TOKEN"`, "-c", `features.multi_agent=false`, "-c", `analytics.enabled=false`}
	env = append(env, "NUCLEAGENT_LOOPBACK_TOKEN=probe-only")
	p, err := platform.Start(platform.Spec{Executable: filepath.Join(generation, b.Entry), Args: args, Env: env, Directory: filepath.Join(root, "workspace")})
	if err != nil {
		return err
	}
	r := newRPC(p)
	defer func() { err = errors.Join(err, r.close()) }()
	deadline, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err = r.call(deadline, "initialize", map[string]any{"clientInfo": map[string]any{"name": "nucleagent_desktop", "title": "NucleAgent", "version": "0.1.0"}}); err != nil {
		return err
	}
	if err = r.notify("initialized", nil); err != nil {
		return err
	}
	raw, err := r.call(deadline, "thread/start", map[string]any{"model": "fixture-only", "modelProvider": "nucleagent_probe", "cwd": filepath.Join(root, "workspace"), "approvalPolicy": "never", "sandbox": "read-only", "ephemeral": true})
	if err != nil {
		return err
	}
	var out struct {
		Thread struct {
			ID string `json:"id"`
		} `json:"thread"`
	}
	if json.Unmarshal(raw, &out) != nil || out.Thread.ID == "" {
		return errors.New("CLI returned no empty session identity")
	}
	_, err = r.call(deadline, "thread/unsubscribe", map[string]any{"threadId": out.Thread.ID})
	return err
}

// Version is a separate check; it never stands in for the protocol probe.
func Version(ctx context.Context, generation string, b catalog.Bundle) error {
	root, err := os.MkdirTemp(filepath.Dir(generation), "version-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	env, err := platform.Environment(root, nil)
	if err != nil {
		return err
	}
	p, err := platform.Start(platform.Spec{Executable: filepath.Join(generation, b.Entry), Args: []string{"--version"}, Env: env, Directory: filepath.Join(root, "workspace")})
	if err != nil {
		return err
	}
	defer p.Close()
	go func() { _, _ = io.Copy(io.Discard, p.Stderr) }()
	result := make(chan []byte, 1)
	go func() { data, _ := io.ReadAll(io.LimitReader(p.Stdout, 4097)); result <- data }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case data := <-result:
		if len(data) > 4096 || !strings.Contains(string(data), b.Version) {
			return errors.New("CLI version differs from catalog")
		}
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.Done():
		return p.Wait()
	}
}
