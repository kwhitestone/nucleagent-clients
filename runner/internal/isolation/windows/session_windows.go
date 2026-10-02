//go:build windows

package isolation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

// Empty-session diagnostic only. Never sends turn/start or a model prompt.
func sessionProbe(input *os.File, process windows.Handle, root string) ([]json.RawMessage, error) {
	var responses []json.RawMessage
	send := func(v any) error { return json.NewEncoder(input).Encode(v) }
	call := func(id int, method string, params any) (json.RawMessage, error) {
		if err := send(map[string]any{"id": id, "method": method, "params": params}); err != nil {
			return nil, err
		}
		until := time.Now().Add(5 * time.Second)
		for time.Now().Before(until) {
			b, err := os.ReadFile(filepath.Join(root, "control", "stdout"))
			if err != nil {
				return nil, err
			}
			for _, line := range bytes.Split(b, []byte("\n")) {
				var reply struct {
					ID            int
					Result, Error json.RawMessage
				}
				if json.Unmarshal(line, &reply) == nil && reply.ID == id {
					responses = append(responses, append(json.RawMessage(nil), line...))
					if len(reply.Error) > 0 && string(reply.Error) != "null" {
						return nil, fmt.Errorf("%s rejected: %s", method, reply.Error)
					}
					return reply.Result, nil
				}
			}
			if w, _ := windows.WaitForSingleObject(process, 0); w == windows.WAIT_OBJECT_0 {
				return nil, fmt.Errorf("CLI exited before %s response", method)
			}
			time.Sleep(20 * time.Millisecond)
		}
		return nil, fmt.Errorf("%s timed out", method)
	}
	if _, err := call(1, "initialize", map[string]any{"clientInfo": map[string]string{"name": "nucleagent_isolation_probe", "version": "0.1.0"}}); err != nil {
		return responses, err
	}
	if err := send(map[string]any{"method": "initialized"}); err != nil {
		return responses, err
	}
	raw, err := call(2, "thread/start", map[string]any{"model": "fixture-only", "modelProvider": "nucleagent_probe", "cwd": filepath.Join(root, "workspace"), "approvalPolicy": "never", "sandbox": "workspace-write", "ephemeral": true})
	if err != nil {
		return responses, err
	}
	var thread struct {
		Sandbox struct{ Type string }
		Thread  struct{ ID string }
	}
	if err = json.Unmarshal(raw, &thread); err != nil {
		return responses, err
	}
	if thread.Sandbox.Type != "workspaceWrite" {
		return responses, fmt.Errorf("isolation policy mismatch: returned sandbox %q", thread.Sandbox.Type)
	}
	_, err = call(3, "thread/unsubscribe", map[string]any{"threadId": thread.Thread.ID})
	return responses, err
}
