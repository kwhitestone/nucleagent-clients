package adapter

import (
	"encoding/json"
	"errors"
	"runtime"
)

func validateSandbox(raw json.RawMessage) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	var out struct {
		Sandbox struct {
			Type string `json:"type"`
		} `json:"sandbox"`
	}
	if json.Unmarshal(raw, &out) != nil || out.Sandbox.Type != "workspaceWrite" {
		return errors.New("Codex did not activate Windows workspaceWrite sandbox")
	}
	return nil
}
