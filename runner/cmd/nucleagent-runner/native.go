package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/nucleagent/nucleagent-shared/a2a"
	"nucleagent-desktop-runner/internal/adapter"
	"nucleagent-desktop-runner/internal/bridge"
	"nucleagent-desktop-runner/internal/catalog"
	"nucleagent-desktop-runner/internal/device"
	"nucleagent-desktop-runner/internal/ledger"
	"nucleagent-desktop-runner/internal/llmproxy"
	"nucleagent-desktop-runner/internal/platform"
	"nucleagent-desktop-runner/internal/vault"
)

func deviceCommand(ctx context.Context, command, root, origin, name string) error {
	store, err := vault.New(filepath.Join(root, "credential"))
	if err != nil {
		return err
	}
	if command == "bind" {
		if _, err := store.Load(); err == nil {
			return errors.New("device already bound; revoke it before rebinding")
		}
		client, err := device.New(origin)
		if err != nil {
			return err
		}
		defer client.Close()
		binding, err := client.Begin(ctx, name, runtime.GOOS, runtime.GOARCH)
		if err != nil {
			return err
		}
		emit(map[string]any{"state": "awaiting-user-confirmation", "id": binding.Challenge.ID, "userCode": binding.Challenge.UserCode, "expiresAt": binding.Challenge.ExpiresAt})
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			credential, err := client.Finish(ctx, binding)
			if err == nil {
				if err := store.Save(credential); err != nil {
					_ = client.Revoke(ctx, credential)
					return err
				}
				emit(map[string]any{"state": "bound", "deviceId": credential.DeviceID})
				return nil
			}
			if !errors.Is(err, device.ErrPending) {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	}
	credential, err := store.Load()
	if err != nil {
		return err
	}
	if command == "device-status" {
		emit(map[string]any{"state": "bound", "deviceId": credential.DeviceID, "coreOrigin": credential.CoreOrigin, "expiresAt": credential.ExpiresAt})
		return nil
	}
	client, err := device.New(credential.CoreOrigin)
	if err != nil {
		return err
	}
	defer client.Close()
	if command == "renew" {
		credential, err = client.Renew(ctx, credential)
		if err != nil {
			return err
		}
		if err := store.Save(credential); err != nil {
			return err
		}
		emit(map[string]any{"state": "renewed", "deviceId": credential.DeviceID})
		return nil
	}
	if err := client.Revoke(ctx, credential); err != nil {
		return err
	}
	if err := store.Delete(); err != nil {
		return err
	}
	emit(map[string]any{"state": "revoked"})
	return nil
}

func runBridge(ctx context.Context, root, generation string, bundle catalog.Bundle) error {
	if err := platform.RequireTaskIsolation(); err != nil {
		return err
	}
	if runtime.GOOS == "windows" && (bundle.WindowsSandbox != "unelevated" || bundle.AdapterVersion != "2") {
		return platform.ErrIsolationUnavailable
	}
	vaultStore, err := vault.New(filepath.Join(root, "credential"))
	if err != nil {
		return err
	}
	credential, err := vaultStore.Load()
	if err != nil {
		return err
	}
	client, err := device.New(credential.CoreOrigin)
	if err != nil {
		return err
	}
	defer client.Close()
	identityHash := sha256.Sum256([]byte(credential.InstanceID))
	store, err := ledger.Open(filepath.Join(root, "ledger", hex.EncodeToString(identityHash[:])), credential.InstanceID)
	if err != nil {
		return err
	}
	// Windows Job Objects reclaim descendants when the runner exits. On macOS
	// abrupt-death cleanup is not yet provable: stop before recovering a live
	// generation, so a new worker cannot overlap an orphaned process group.
	if runtime.GOOS == "darwin" {
		for _, record := range store.Records() {
			if record.Result == nil {
				return errors.New("interrupted macOS worker requires process cleanup before recovery")
			}
		}
	}
	// The application lock is already held. No worker is resumed from disk.
	if err := store.Recover(); err != nil {
		return err
	}
	reported := map[string]string{}
	for ctx.Err() == nil {
		if time.Until(credential.ExpiresAt) < time.Hour {
			credential, err = client.Renew(ctx, credential)
			if err != nil {
				return err
			}
			if err := vaultStore.Save(credential); err != nil {
				return err
			}
		}
		endpoint, err := client.Register(ctx, credential)
		if errors.Is(err, device.ErrUnauthorized) {
			return err
		}
		if err == nil {
			b, makeErr := bridge.New(bridge.Config{Credential: credential, OS: runtime.GOOS, Arch: runtime.GOARCH, Backends: []a2a.PCBackendAdmission{{ID: "codex", Generation: bundle.ID, CLIVersion: bundle.Version, AdapterVersion: bundle.AdapterVersion, ProtocolVersion: "app-server-v2", Tools: true}}}, store, executeNative(root, generation, bundle, credential, client))
			if makeErr != nil {
				return makeErr
			}
			ws, dialErr := bridge.Dial(ctx, endpoint, credential)
			if dialErr == nil {
				connectionCtx, cancel := context.WithCancel(ctx)
				done := make(chan error, 1)
				go func() { done <- b.Serve(connectionCtx, ws) }()
				ticker := time.NewTicker(250 * time.Millisecond)
				connected, enabled := true, false
				lastState := ""
				for connected {
					select {
					case <-ctx.Done():
						cancel()
					case <-done:
						connected = false
					case <-ticker.C:
						for _, record := range store.Records() {
							state := "running"
							if record.Result != nil {
								state = "awaiting-ack"
							}
							if record.Acknowledged {
								state = "acknowledged"
							}
							if reported[record.Key.ID()] != state {
								status := ""
								if record.Result != nil {
									status = record.Result.Status
								}
								emit(map[string]any{"state": state, "conversationId": record.ConversationID, "stepId": record.StepID, "executionNonce": record.Nonce, "resultStatus": status})
								reported[record.Key.ID()] = state
							}
						}
						snapshot := b.Snapshot()
						if time.Until(credential.ExpiresAt) < time.Hour && snapshot.Active == "" {
							cancel()
						}
						if snapshot.State == "paused" && !enabled && !store.Unsafe() {
							controlCtx, stop := context.WithTimeout(connectionCtx, 3*time.Second)
							if err := b.SetEnabled(controlCtx, true, true); err != nil {
								cancel()
							}
							stop()
							enabled = true
						}
						if snapshot.State != lastState {
							emit(map[string]any{"admission": snapshot.State, "deviceId": credential.DeviceID, "active": snapshot.Active})
							lastState = snapshot.State
						}
					}
				}
				ticker.Stop()
				cancel()
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(2 * time.Second):
		}
	}
	return nil
}

func executeNative(root, generation string, bundle catalog.Bundle, credential vault.Credential, client *device.Client) bridge.Execute {
	return func(ctx context.Context, request a2a.ExecutionRequest, backend, selectedGeneration string, emitEvent func(a2a.A2AStreamEventPayload) error) bridge.Outcome {
		out := bridge.Outcome{Result: a2a.ExecutionResult{StepID: request.StepID, Status: "failed", ErrorCode: "native_execution_failed"}, Clean: true, Integrity: true}
		if platform.RequireTaskIsolation() != nil || runtime.GOOS == "windows" && (bundle.WindowsSandbox != "unelevated" || bundle.AdapterVersion != "2") {
			out.Result.ErrorCode = "isolation_unavailable"
			return out
		}
		if backend != "codex" || selectedGeneration != bundle.ID || catalog.Verify(generation, bundle) != nil {
			out.Integrity = false
			return out
		}
		jobs := filepath.Join(root, "tasks")
		if platform.PrivateDirectory(jobs) != nil {
			return out
		}
		taskRoot, err := os.MkdirTemp(jobs, "task-")
		if err != nil {
			return out
		}
		if err := platform.PrivateDirectory(taskRoot); err != nil {
			return out
		}
		if err := adapter.InstallSkills(ctx, taskRoot, request.SkillBindings); err != nil {
			out.Result.ErrorCode = "skill_install_failed"
			return out
		}
		key := ""
		for name, value := range request.Headers {
			if strings.EqualFold(name, "x-llm-proxy-key") {
				key = value
			}
		}
		if request.ModelLimits == nil {
			return out
		}
		proxy, err := llmproxy.Start(ctx, llmproxy.Scope{CoreOrigin: credential.CoreOrigin, Key: key, Model: request.Model, MaxOutputTokens: request.ModelLimits.MaxOutputTokens, API: "responses"})
		if err != nil {
			return out
		}
		defer proxy.Close()
		out.Result, out.Clean = adapter.ExecuteCodex(ctx, taskRoot, generation, bundle, request, proxy.URL, proxy.Token, emitEvent)
		out.Integrity = catalog.Verify(generation, bundle) == nil
		if !out.Clean || !out.Integrity || out.Result.Status != "completed" {
			return out
		}
		files, err := os.ReadDir(filepath.Join(taskRoot, "workspace", "artifacts"))
		if err != nil {
			out.Result.Status, out.Result.ErrorCode = "failed", "artifact_scan_failed"
			return out
		}
		if len(files) > 10 {
			out.Result.Status, out.Result.ErrorCode = "failed", "artifact_limit_exceeded"
			return out
		}
		for _, file := range files {
			if file.IsDir() {
				continue
			}
			attachment, err := client.UploadArtifact(ctx, credential, request, filepath.Join(taskRoot, "workspace", "artifacts", file.Name()))
			if err != nil {
				out.Result.Status, out.Result.ErrorCode = "failed", "artifact_upload_failed"
				return out
			}
			out.Result.Attachments = append(out.Result.Attachments, attachment)
		}
		return out
	}
}
