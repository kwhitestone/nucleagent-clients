package adapter

import (
	"bufio"
	"context"
	"encoding/json"
	"nucleagent-desktop-runner/internal/platform"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRPCFixture(t *testing.T) {
	if os.Getenv("G9_RPC_FIXTURE") != "1" {
		return
	}
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		os.Exit(2)
	}
	var request map[string]json.RawMessage
	if json.Unmarshal(scanner.Bytes(), &request) != nil {
		os.Exit(3)
	}
	out := json.NewEncoder(os.Stdout)
	_ = out.Encode(map[string]any{"id": "approval-1", "method": "item/commandExecution/requestApproval", "params": map[string]string{"command": "must not execute"}})
	if !scanner.Scan() {
		os.Exit(4)
	}
	var response map[string]json.RawMessage
	if json.Unmarshal(scanner.Bytes(), &response) != nil || len(response["error"]) == 0 || len(response["result"]) > 0 {
		os.Exit(5)
	}
	_ = out.Encode(map[string]any{"id": request["id"], "result": map[string]bool{"approvalDenied": true}})
	for scanner.Scan() {
	}
	os.Exit(0)
}

func TestRPCDeniesInteractiveRequestsAndCleansUp(t *testing.T) {
	root := t.TempDir()
	env, err := platform.Environment(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p, err := platform.Start(platform.Spec{Executable: executable, Args: []string{"-test.run=^TestRPCFixture$"}, Env: append(env, "G9_RPC_FIXTURE=1"), Directory: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	r := newRPC(p)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := r.call(ctx, "initialize", map[string]any{})
	if err != nil {
		r.close()
		t.Fatal(err)
	}
	var value struct {
		ApprovalDenied bool `json:"approvalDenied"`
	}
	if json.Unmarshal(result, &value) != nil || !value.ApprovalDenied {
		t.Fatal("approval was not explicitly denied")
	}
	if err = r.close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.Done():
	case <-ctx.Done():
		t.Fatal("worker survived adapter close")
	}
}
