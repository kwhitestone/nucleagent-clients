package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nucleagent/nucleagent-shared/a2a"
	"nucleagent-desktop-runner/internal/catalog"
)

func TestCodexTurnRequiresMatchingTerminalIdentity(t *testing.T) {
	c := &codexTurn{thread: "thread", turn: "turn", redact: func(s string) string { return s }, emit: func(a2a.A2AStreamEventPayload) error { return nil }}
	for _, raw := range []string{`{"threadId":"thread","turn":{"id":"foreign","status":"completed"}}`, `{"threadId":"thread","turn":{"status":"completed"}}`} {
		if c.notification(rpcMessage{Method: "turn/completed", Params: json.RawMessage(raw)}) == nil || c.complete {
			t.Fatal("foreign or missing turn accepted")
		}
	}
	if err := c.notification(rpcMessage{Method: "turn/completed", Params: json.RawMessage(`{"threadId":"thread","turn":{"id":"turn","status":"failed"}}`)}); err != nil || c.status != "failed" {
		t.Fatal("terminal failure lost", err)
	}
}

// Uses the actual pinned CLI against a local fake Responses service. No cloud
// inference, OAuth credentials, executable tools or paid task quota are used.
func TestCodexExecuteOfflineResponses(t *testing.T) {
	dir := os.Getenv("G9_CODEX_PROTOCOL_FIXTURE")
	if dir == "" {
		t.Skip("requires the verified native Codex protocol fixture")
	}
	if !filepath.IsAbs(dir) {
		t.Fatal("absolute fixture required")
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || !strings.HasSuffix(r.URL.Path, "/responses") || r.Header.Get("Authorization") != "Bearer offline-token" {
			http.Error(w, "invalid offline request", 400)
			return
		}
		calls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		event := func(kind string, value any) {
			data, _ := json.Marshal(value)
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", kind, data)
			w.(http.Flusher).Flush()
		}
		item := map[string]any{"id": "msg_fixture", "type": "message", "role": "assistant", "status": "completed", "content": []any{map[string]any{"type": "output_text", "text": "Offline native result.", "annotations": []any{}}}}
		response := map[string]any{"id": "resp_fixture", "object": "response", "model": "fixture", "status": "in_progress", "output": []any{}}
		event("response.created", map[string]any{"type": "response.created", "response": response})
		event("response.output_item.added", map[string]any{"type": "response.output_item.added", "output_index": 0, "item": item})
		event("response.output_text.delta", map[string]any{"type": "response.output_text.delta", "item_id": "msg_fixture", "output_index": 0, "content_index": 0, "delta": "Offline native result."})
		event("response.output_item.done", map[string]any{"type": "response.output_item.done", "output_index": 0, "item": item})
		response["status"], response["output"], response["usage"] = "completed", []any{item}, map[string]int{"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}
		event("response.completed", map[string]any{"type": "response.completed", "response": response})
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var output strings.Builder
	result, clean := ExecuteCodex(ctx, t.TempDir(), dir, catalog.Bundle{Backend: "codex", Entry: "bin/codex", Version: "0.149.1"}, a2a.ExecutionRequest{StepID: "offline", Model: "fixture", Input: "Return the offline fixture text; do not call tools."}, server.URL+"/v1", "offline-token", func(p a2a.A2AStreamEventPayload) error { output.WriteString(p.Content); return nil })
	if result.Status != "completed" || !clean || calls.Load() != 1 || !strings.Contains(output.String(), "Offline native result.") || result.Output != output.String() {
		t.Fatalf("native protocol: status=%s code=%s clean=%t calls=%d streamed=%q result=%q", result.Status, result.ErrorCode, clean, calls.Load(), output.String(), result.Output)
	}
}
