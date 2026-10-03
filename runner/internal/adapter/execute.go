package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/nucleagent/nucleagent-shared/a2a"
	"nucleagent-desktop-runner/internal/catalog"
	"nucleagent-desktop-runner/internal/platform"
)

type codexTurn struct {
	thread, turn string
	output       strings.Builder
	complete     bool
	status       string
	emit         func(a2a.A2AStreamEventPayload) error
	redact       func(string) string
}

func (c *codexTurn) notification(msg rpcMessage) error {
	var p struct {
		ThreadID string `json:"threadId"`
		TurnID   string `json:"turnId"`
		Delta    string `json:"delta"`
		Turn     struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"turn"`
	}
	if json.Unmarshal(msg.Params, &p) != nil {
		return errors.New("invalid CLI event")
	}
	if p.ThreadID != c.thread {
		return nil
	}
	if msg.Method == "turn/completed" {
		if p.Turn.ID == "" || c.turn != "" && c.turn != p.Turn.ID {
			return errors.New("CLI turn identity mismatch")
		}
		c.turn, c.status, c.complete = p.Turn.ID, p.Turn.Status, true
		return nil
	}
	if msg.Method != "item/agentMessage/delta" {
		return nil
	}
	if p.TurnID == "" || c.turn != "" && p.TurnID != c.turn {
		return errors.New("CLI stream identity mismatch")
	}
	c.turn = p.TurnID
	if c.output.Len()+len(p.Delta) > 256<<10 {
		return errors.New("CLI output limit exceeded")
	}
	c.output.WriteString(c.redact(p.Delta))
	return c.emit(a2a.A2AStreamEventPayload{EventType: "text_delta", Content: c.redact(p.Delta)})
}

// ExecuteCodex uses the generated 0.149.1 app-server protocol. Completion is a
// turn status, never EOF or the process exit code. Core keys are absent from
// the worker environment; only the per-task loopback token is supplied.
func ExecuteCodex(ctx context.Context, root, generation string, bundle catalog.Bundle, request a2a.ExecutionRequest, endpoint, token string, emit func(a2a.A2AStreamEventPayload) error) (result a2a.ExecutionResult, clean bool) {
	result = a2a.ExecutionResult{StepID: request.StepID, Status: "failed", ErrorCode: "cli_execution_failed"}
	clean = true
	if bundle.Backend != "codex" || request.Model == "" || !strings.HasPrefix(endpoint, "http://127.0.0.1:") {
		return
	}
	env, err := platform.Environment(root, []string{filepath.Dir(filepath.Join(generation, bundle.Entry))})
	if err != nil {
		return
	}
	if err := platform.PrepareCodexConfig(root); err != nil {
		return
	}
	workspace := filepath.Join(root, "workspace")
	if err := prepareArtifactDirectory(workspace); err != nil {
		return result, true
	}
	args := []string{"app-server", "--listen", "stdio://", "-c", `model_provider="nucleagent"`, "-c", `model_providers.nucleagent.name="NucleAgent"`, "-c", `model_providers.nucleagent.base_url="` + endpoint + `"`, "-c", `model_providers.nucleagent.wire_api="responses"`, "-c", `model_providers.nucleagent.requires_openai_auth=false`, "-c", `model_providers.nucleagent.env_key="NUCLEAGENT_LOOPBACK_TOKEN"`, "-c", `model_providers.nucleagent.supports_websockets=false`, "-c", `features.multi_agent=false`, "-c", `features.apps=false`, "-c", `features.web_search_request=false`, "-c", `web_search="disabled"`, "-c", `analytics.enabled=false`}
	env = append(env, "NUCLEAGENT_LOOPBACK_TOKEN="+token)
	process, err := platform.Start(platform.Spec{Executable: filepath.Join(generation, bundle.Entry), Args: args, Env: env, Directory: workspace})
	if err != nil {
		return
	}
	r := newRPC(process)
	defer func() { clean = r.close() == nil }()
	if _, err := r.call(ctx, "initialize", map[string]any{"clientInfo": map[string]any{"name": "nucleagent_desktop", "title": "NucleAgent", "version": "0.2.0"}}); err != nil {
		return result, clean
	}
	if r.notify("initialized", nil) != nil {
		return result, clean
	}
	raw, err := r.call(ctx, "thread/start", map[string]any{"model": request.Model, "modelProvider": "nucleagent", "cwd": workspace, "approvalPolicy": "never", "ephemeral": true, "developerInstructions": "Save final deliverable files in the artifacts directory. Do not use subagents, browsers, desktop tools or plugins."})
	if err != nil {
		return result, clean
	}
	var started struct {
		Thread struct {
			ID string `json:"id"`
		} `json:"thread"`
	}
	if json.Unmarshal(raw, &started) != nil || started.Thread.ID == "" {
		return result, clean
	}
	if err := validateSandbox(raw); err != nil {
		result.ErrorCode = "sandbox_policy_mismatch"
		return result, clean
	}
	state := &codexTurn{thread: started.Thread.ID, emit: emit, redact: func(value string) string { return strings.ReplaceAll(value, token, "[redacted]") }}
	r.onNotify = state.notification
	input := request.Input
	if len(request.Context) > 0 {
		input = "Previous conversation context:\n" + string(request.Context) + "\n\nCurrent request:\n" + input
	}
	items := []map[string]any{{"type": "text", "text": input}}
	for _, binding := range request.SkillBindings {
		items = append(items, map[string]any{"type": "skill", "name": binding.Slug, "path": filepath.Join(workspace, ".agents", "skills", binding.Slug, "SKILL.md")})
	}
	raw, err = r.call(ctx, "turn/start", map[string]any{"threadId": state.thread, "input": items})
	if err != nil {
		return result, clean
	}
	var turn struct {
		Turn struct {
			ID string `json:"id"`
		} `json:"turn"`
	}
	if json.Unmarshal(raw, &turn) != nil || turn.Turn.ID == "" || state.turn != "" && state.turn != turn.Turn.ID {
		return result, clean
	}
	state.turn = turn.Turn.ID
	for !state.complete {
		select {
		case <-ctx.Done():
			result.Status, result.ErrorCode = "cancelled", "execution_cancelled"
			return result, clean
		case msg, ok := <-r.messages:
			if !ok {
				return result, clean
			}
			if msg.Method != "" && len(msg.ID) > 0 {
				if r.send(map[string]any{"id": msg.ID, "error": map[string]any{"code": -32601, "message": "interactive requests unsupported"}}) != nil {
					return result, clean
				}
				continue
			}
			if err := state.notification(msg); err != nil {
				return result, clean
			}
		}
	}
	result.Output = state.redact(state.output.String())
	if state.status == "completed" {
		result.Status, result.ErrorCode = "completed", ""
	} else if state.status == "interrupted" {
		result.Status, result.ErrorCode = "cancelled", "execution_cancelled"
	}
	return result, clean
}

// Inherit the private workspace ACL, including Codex sandbox grants added at
// launch. A protected child DACL would block the restricted worker token.
func prepareArtifactDirectory(workspace string) error {
	return os.MkdirAll(filepath.Join(workspace, "artifacts"), 0700)
}
