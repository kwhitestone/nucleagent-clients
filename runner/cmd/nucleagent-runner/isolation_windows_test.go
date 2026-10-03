//go:build windows

package main

import (
	"context"
	"os"
	"testing"

	"github.com/nucleagent/nucleagent-shared/a2a"
	"nucleagent-desktop-runner/internal/catalog"
	"nucleagent-desktop-runner/internal/platform"
	"nucleagent-desktop-runner/internal/vault"
)

func TestWindowsInvalidGenerationRefusedBeforeTask(t *testing.T) {
	root := t.TempDir()
	if err := platform.RequireTaskIsolation(); err != nil {
		t.Fatalf("bridge admitted without isolation: %v", err)
	}
	emitted := false
	execute := executeNative(root, "missing", catalog.Bundle{}, vault.Credential{}, nil)
	out := execute(context.Background(), a2a.ExecutionRequest{StepID: "refused"}, "codex", "missing", func(a2a.A2AStreamEventPayload) error { emitted = true; return nil })
	if out.Result.Status != "failed" || out.Result.ErrorCode != "isolation_unavailable" || !out.Clean || emitted {
		t.Fatalf("unexpected admission result: %+v", out)
	}
	files, err := os.ReadDir(root)
	if err != nil || len(files) != 0 {
		t.Fatalf("task side effects before isolation: %v %v", files, err)
	}
}
