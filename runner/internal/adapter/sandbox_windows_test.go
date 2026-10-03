//go:build windows

package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nucleagent-desktop-runner/internal/platform"
)

// Uses the production launcher and task config. No model, credential, turn/start
// or sandboxPolicy override is used; command/exec inherits the effective policy.
func TestWindowsCodexSandbox(t *testing.T) {
	exe := os.Getenv("G9_WINDOWS_CODEX_FIXTURE")
	if exe == "" {
		t.Skip("requires pinned native Windows Codex fixture")
	}
	root := t.TempDir()
	if base := os.Getenv("G9_WINDOWS_EVIDENCE_ROOT"); base != "" {
		var err error
		root, err = os.MkdirTemp(base, "sandbox-")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("retainedEvidence=%s", root)
	}
	env, err := platform.Environment(root, []string{filepath.Dir(exe)})
	if err != nil {
		t.Fatal(err)
	}
	if err = platform.PrepareCodexConfig(root); err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(root, "workspace")
	if err := prepareArtifactDirectory(workspace); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside-canary.txt")
	if err = os.WriteFile(outside, []byte("UNCHANGED"), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"app-server", "--listen", "stdio://", "-c", `model_provider="fixture"`, "-c", `model_providers.fixture.name="fixture"`, "-c", `model_providers.fixture.base_url="http://127.0.0.1:1/v1"`, "-c", `model_providers.fixture.wire_api="responses"`, "-c", `model_providers.fixture.requires_openai_auth=false`, "-c", `features.multi_agent=false`, "-c", `analytics.enabled=false`}
	p, err := platform.Start(platform.Spec{Executable: exe, Args: args, Env: env, Directory: workspace})
	if err != nil {
		t.Fatal(err)
	}
	r := newRPC(p)
	defer func() {
		if err := r.close(); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	init, err := r.call(ctx, "initialize", map[string]any{"clientInfo": map[string]string{"name": "runner_acceptance", "version": "1"}, "capabilities": map[string]bool{"experimentalApi": true}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("initialize=%s", init)
	if err = r.notify("initialized", nil); err != nil {
		t.Fatal(err)
	}
	thread, err := r.call(ctx, "thread/start", map[string]any{"cwd": workspace, "approvalPolicy": "never", "ephemeral": true})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("thread/start=%s", thread)
	if err = validateSandbox(thread); err != nil {
		t.Fatal(err)
	}
	command := func(script string) int {
		raw, err := r.call(ctx, "command/exec", map[string]any{"command": []string{filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"), "/d", "/c", script}, "cwd": workspace, "timeoutMs": 60000})
		if err != nil {
			var remote *protocolError
			if errors.As(err, &remote) {
				t.Logf("full credential-free error=%s", remote.response)
			}
			t.Fatal(err)
		}
		t.Logf("command/exec=%s", raw)
		var out struct{ ExitCode int }
		if err = json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		return out.ExitCode
	}
	if command("echo runner-native-proof>inside-proof.txt && type inside-proof.txt && whoami /groups") != 0 {
		t.Fatal("workspace write failed")
	}
	data, err := os.ReadFile(filepath.Join(workspace, "inside-proof.txt"))
	if err != nil || strings.TrimSpace(string(data)) != "runner-native-proof" {
		t.Fatal("proof file missing", err)
	}
	if command("echo nested-native-proof>artifacts\\inside-proof.txt && type artifacts\\inside-proof.txt") != 0 {
		t.Fatal("precreated artifact directory write failed")
	}
	data, err = os.ReadFile(filepath.Join(workspace, "artifacts", "inside-proof.txt"))
	if err != nil || strings.TrimSpace(string(data)) != "nested-native-proof" {
		t.Fatal("broker could not read sandbox artifact", err)
	}
	if command("echo MODIFIED>..\\outside-canary.txt") == 0 {
		t.Fatal("outside write accepted")
	}
	data, err = os.ReadFile(outside)
	if err != nil || string(data) != "UNCHANGED" {
		t.Fatal("outside canary changed", err)
	}
}
