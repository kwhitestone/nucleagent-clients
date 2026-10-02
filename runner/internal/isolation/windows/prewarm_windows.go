//go:build windows

package isolation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type PrewarmEvidence struct {
	Home        string
	Copied      bool
	Initialized bool
	Response    json.RawMessage
	Stderr      string
	Files       []string
}

// Trusted broker bootstrap only: fresh empty home, allowlisted environment,
// no authentication, no inherited configuration and no turn/start.
func prewarmHome(exe string, args, env []string, root, sid string, copyHome bool) (*PrewarmEvidence, error) {
	e := &PrewarmEvidence{Home: filepath.Join(root, "home"), Copied: copyHome}
	if copyHome {
		e.Home = filepath.Join(root, "control", "warm-seed")
	}
	if err := os.MkdirAll(e.Home, 0700); err != nil {
		return e, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Dir = filepath.Join(root, "workspace")
	cmd.Env = append([]string(nil), env...)
	for i, v := range cmd.Env {
		if strings.HasPrefix(v, "CODEX_HOME=") {
			cmd.Env[i] = "CODEX_HOME=" + e.Home
		}
	}
	cmd.WaitDelay = 2 * time.Second
	outPath := filepath.Join(root, "control", "prewarm-stdout")
	errPath := filepath.Join(root, "control", "prewarm-stderr")
	out, err := os.Create(outPath)
	if err != nil {
		return e, err
	}
	defer out.Close()
	stderr, err := os.Create(errPath)
	if err != nil {
		return e, err
	}
	defer stderr.Close()
	cmd.Stdout, cmd.Stderr = out, stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		return e, err
	}
	if err = cmd.Start(); err != nil {
		return e, err
	}
	writeErr := json.NewEncoder(in).Encode(map[string]any{"id": 1, "method": "initialize", "params": map[string]any{"clientInfo": map[string]string{"name": "nucleagent_prewarm_probe", "version": "0.1.0"}}})
	if writeErr == nil {
		for ctx.Err() == nil && !e.Initialized {
			b, readErr := os.ReadFile(outPath)
			if readErr != nil {
				break
			}
			for _, line := range bytes.Split(b, []byte("\n")) {
				var reply struct {
					ID            int
					Result, Error json.RawMessage
				}
				if json.Unmarshal(line, &reply) == nil && reply.ID == 1 {
					e.Response = append(json.RawMessage(nil), line...)
					e.Initialized = len(reply.Result) > 0 && (len(reply.Error) == 0 || string(reply.Error) == "null")
					break
				}
			}
			if !e.Initialized {
				time.Sleep(20 * time.Millisecond)
			}
		}
	}
	in.Close()
	err = cmd.Wait()
	b, _ := os.ReadFile(errPath)
	e.Stderr = string(b)
	if err != nil {
		return e, fmt.Errorf("broker prewarm: %w", err)
	}
	if !e.Initialized {
		return e, fmt.Errorf("broker prewarm initialize missing")
	}
	err = filepath.Walk(e.Home, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if err = checkPath(path); err != nil {
			return err
		}
		rel, err := filepath.Rel(e.Home, path)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			e.Files = append(e.Files, rel)
		}
		dest := path
		if copyHome {
			dest = filepath.Join(root, "home", rel)
			if info.IsDir() {
				err = os.MkdirAll(dest, 0700)
			} else {
				err = copyProbeFile(path, dest)
			}
			if err != nil {
				return err
			}
		}
		return SetProbeACL(dest, sid, true)
	})
	return e, err
}
