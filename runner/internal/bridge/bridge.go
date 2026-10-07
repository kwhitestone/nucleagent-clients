// Package bridge owns one authenticated executorreg connection. Execution
// inputs and credentials remain in memory; only the ledger's projection persists.
package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/nucleagent/nucleagent-shared/a2a"
	"nucleagent-desktop-runner/internal/admission"
	"nucleagent-desktop-runner/internal/ledger"
	"nucleagent-desktop-runner/internal/vault"
)

type Outcome struct {
	Result           a2a.ExecutionResult
	Clean, Integrity bool
}
type Execute func(context.Context, a2a.ExecutionRequest, string, string, func(a2a.A2AStreamEventPayload) error) Outcome
type Config struct {
	Credential vault.Credential
	OS, Arch   string
	Backends   []a2a.PCBackendAdmission
}
type control struct {
	enabled, consent bool
	result           chan error
}
type Bridge struct {
	cfg      Config
	gate     *admission.Gate
	ledger   *ledger.Store
	execute  Execute
	controls chan control
	write    sync.Mutex
	serve    sync.Mutex
}

func New(cfg Config, store *ledger.Store, execute Execute) (*Bridge, error) {
	if cfg.Credential.DeviceID == "" || cfg.Credential.InstanceID == "" || store == nil || execute == nil {
		return nil, errors.New("incomplete bridge configuration")
	}
	b := &Bridge{cfg: cfg, gate: admission.New(), ledger: store, execute: execute, controls: make(chan control)}
	seen := map[string]bool{}
	for _, backend := range cfg.Backends {
		if seen[backend.ID] || backend.Generation == "" || backend.CLIVersion == "" || backend.AdapterVersion == "" || backend.ProtocolVersion == "" || backend.Subagents || backend.Attachments {
			return nil, errors.New("invalid backend admission")
		}
		seen[backend.ID] = true
		if err := b.gate.SetBackend(backend.ID, backend.Generation); err != nil {
			return nil, err
		}
	}
	return b, nil
}
func (b *Bridge) Snapshot() admission.Snapshot { return b.gate.Snapshot() }
func (b *Bridge) SetEnabled(ctx context.Context, enabled, consent bool) error {
	if enabled && b.ledger.Unsafe() {
		return errors.New("persistent cleanup or integrity fence requires repair")
	}
	// Local pause is immediate even if the websocket is stalled.
	if !enabled {
		b.gate.Pause()
	}
	c := control{enabled: enabled, consent: consent, result: make(chan error, 1)}
	select {
	case b.controls <- c:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-c.result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
func Dial(ctx context.Context, endpoint string, credential vault.Credential) (*websocket.Conn, error) {
	u, err := url.Parse(endpoint)
	base, baseErr := url.Parse(credential.CoreOrigin)
	if err != nil || baseErr != nil || base.Scheme != "https" || u.Scheme != "wss" || u.Host != base.Host || u.Path != a2a.PCNativePath+"/ws" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("untrusted private websocket endpoint")
	}
	d := websocket.Dialer{HandshakeTimeout: 15 * time.Second, Proxy: http.ProxyFromEnvironment}
	ws, res, err := d.DialContext(ctx, endpoint, http.Header{"Authorization": []string{credential.Token}}) // bare: Kong 403s Bearer
	if res != nil && res.Body != nil {
		res.Body.Close()
	}
	if err != nil {
		return nil, errors.New("private websocket unavailable")
	}
	return ws, nil
}
func (b *Bridge) send(ws *websocket.Conn, kind, request string, payload any) error {
	env, err := a2a.NewEnvelopeWithRequest(time.Now().UnixMilli(), kind, request, payload)
	if err != nil {
		return err
	}
	frames, err := a2a.EncodeEnvelopeFrames(env)
	if err != nil {
		return err
	}
	b.write.Lock()
	defer b.write.Unlock()
	for _, frame := range frames {
		if err = ws.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return errors.New("websocket closed")
		}
		if err = ws.WriteMessage(websocket.TextMessage, frame); err != nil {
			return errors.New("websocket write failed")
		}
	}
	return nil
}
func (b *Bridge) admission() a2a.PCAdmission {
	s := b.gate.Snapshot()
	state := s.State
	if state == "syncing" {
		state = "ready"
	}
	backends := append([]a2a.PCBackendAdmission(nil), b.cfg.Backends...)
	for i := range backends {
		backends[i].State = state
	}
	return a2a.PCAdmission{Contract: a2a.PCContractV1, Revision: s.Revision, State: state, Backends: backends}
}
func (b *Bridge) result(ws *websocket.Conn, r ledger.Record) error {
	raw, err := json.Marshal(r.Result)
	if err != nil {
		return err
	}
	return b.send(ws, a2a.EnvA2ATaskResult, r.RequestID, a2a.A2ATaskResultPayload{ConversationID: r.ConversationID, StepID: r.StepID, ExecutionNonce: r.Nonce, Status: r.Result.Status, Body: raw})
}
func (b *Bridge) pending(ws *websocket.Conn) error {
	for _, r := range b.ledger.Records() {
		if r.Result != nil && !r.Acknowledged {
			if err := b.result(ws, r); err != nil {
				return err
			}
		}
	}
	return nil
}

// Serve returns only after the in-flight worker's cleanup and durable terminal
// transition. The owner must not reconnect or release its process lock sooner.
func (b *Bridge) Serve(parent context.Context, ws *websocket.Conn) (err error) {
	if !b.serve.TryLock() {
		return errors.New("bridge already connected")
	}
	defer b.serve.Unlock()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	epoch := b.gate.Connect()
	stop := context.AfterFunc(ctx, func() { _ = ws.Close() })
	defer stop()
	var jobs sync.WaitGroup
	defer func() { b.gate.Disconnect(epoch); cancel(); _ = ws.Close(); jobs.Wait() }()
	ws.SetReadLimit(a2a.MaxEnvelopeBytes + 4096)
	pc := b.admission()
	pc.State = a2a.PCPaused
	for i := range pc.Backends {
		pc.Backends[i].State = a2a.PCPaused
	}
	handshake := a2a.HandshakePayload{DeviceID: b.cfg.Credential.DeviceID, InstanceID: b.cfg.Credential.InstanceID, OS: b.cfg.OS, Arch: b.cfg.Arch, AppVersion: "0.2.0", PC: &pc, Capacity: &a2a.ExecutorCapacity{MaxConcurrency: 1, SnapshotComplete: true}}
	for _, record := range b.ledger.Records() {
		if !record.Acknowledged {
			handshake.Capacity.ActiveExecutions = append(handshake.Capacity.ActiveExecutions, a2a.A2AHeartbeatBatchItem{ConversationID: record.ConversationID, StepID: record.StepID, ExecutionNonce: record.Nonce, Capability: record.Backend, Status: "running"})
		}
	}
	for _, backend := range b.cfg.Backends {
		handshake.Executors = append(handshake.Executors, a2a.DesktopExecutor{ID: backend.ID, Type: backend.ID, DisplayName: backend.ID, Streaming: true, MaxConcurrency: 1})
	}
	if err = b.send(ws, a2a.EnvHandshake, "", handshake); err != nil {
		return err
	}
	_ = ws.SetReadDeadline(time.Now().Add(15 * time.Second))
	var first a2a.Envelope
	var ack a2a.HandshakeAckPayload
	if ws.ReadJSON(&first) != nil || first.Version != 1 || first.Type != a2a.EnvHandshakeAck || first.ParsePayload(&ack) != nil || ack.Status != "ok" || ack.AdmissionRevision != pc.Revision {
		return errors.New("private handshake not acknowledged")
	}
	if err = b.gate.Negotiate(epoch, ack.PCContract); err != nil {
		return err
	}
	if err = b.gate.Ack(epoch, ack.AdmissionRevision); err != nil {
		return err
	}
	if err = b.pending(ws); err != nil {
		return err
	}
	frames := make(chan *a2a.Envelope)
	readError := make(chan error, 1)
	go func() {
		reader := newReader(ws)
		for {
			env, e := reader.read()
			if e != nil {
				readError <- e
				return
			}
			select {
			case frames <- env:
			case <-ctx.Done():
				return
			}
		}
	}()
	finished := make(chan error, 1)
	var taskCancel context.CancelFunc
	var active *ledger.Record
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-readError:
			return e
		case e := <-finished:
			if active != nil {
				if record, ok := b.ledger.Get(active.Key); ok && record.Acknowledged {
					_ = b.gate.Finish(active.Key.ID(), true, true)
				}
			}
			active = nil
			taskCancel = nil
			if e != nil {
				return e
			}
		case c := <-b.controls:
			var e error
			if c.enabled {
				_, e = b.gate.Enable(c.consent)
			}
			if e == nil {
				e = b.send(ws, a2a.EnvPCAdmission, "", b.admission())
			}
			c.result <- e
			if e != nil && c.enabled && b.gate.Snapshot().State == "syncing" {
				return e
			}
		case <-ticker.C:
			if err = b.send(ws, a2a.EnvPing, "", a2a.PingPayload{SentAt: time.Now().UnixMilli()}); err != nil {
				return err
			}
			items := []a2a.A2AHeartbeatBatchItem{}
			if active != nil {
				items = append(items, a2a.A2AHeartbeatBatchItem{ConversationID: active.ConversationID, StepID: active.StepID, ExecutionNonce: active.Nonce, Capability: active.Backend, Status: "running", StartedAt: active.StartedAt.UnixMilli(), UpdatedAt: time.Now().UnixMilli()})
			}
			if err = b.send(ws, a2a.EnvA2AHeartbeatBatch, "", a2a.A2AHeartbeatBatchPayload{Items: items, SentAt: time.Now().UnixMilli()}); err != nil {
				return err
			}
			if err = b.pending(ws); err != nil {
				return err
			}
		case env := <-frames:
			switch env.Type {
			case a2a.EnvPCAdmissionAck:
				var p a2a.PCAdmissionAck
				if env.ParsePayload(&p) != nil || p.Status != "ok" {
					b.gate.Pause()
					return errors.New("admission rejected")
				}
				// A delayed ACK cannot reopen a newer paused revision.
				_ = b.gate.Ack(epoch, p.Revision)
			case a2a.EnvPing:
				var p a2a.PingPayload
				_ = env.ParsePayload(&p)
				if err = b.send(ws, a2a.EnvPong, env.ID, a2a.PongPayload{SentAt: p.SentAt, ReceivedAt: time.Now().UnixMilli()}); err != nil {
					return err
				}
			case a2a.EnvTaskKill:
				var p a2a.TaskKillPayload
				if env.ParsePayload(&p) == nil && active != nil && p.StepID == active.StepID && p.ExecutionNonce == active.Nonce {
					for _, id := range p.ConversationIDs {
						if id == active.ConversationID && taskCancel != nil {
							taskCancel()
						}
					}
				}
			case a2a.EnvA2ATaskResultAck:
				var p a2a.A2ATaskResultAckPayload
				if env.ParsePayload(&p) != nil || p.Status != "accepted" && p.Status != "duplicate" {
					continue
				}
				for _, r := range b.ledger.Records() {
					if r.Result != nil && !r.Acknowledged && r.ConversationID == p.ConversationID && r.StepID == p.StepID && r.Nonce == p.ExecutionNonce && r.RequestID == env.RequestID {
						if err = b.ledger.Ack(r.Key, r.RequestID); err != nil {
							return err
						}
						if active == nil && b.gate.Snapshot().Active == r.Key.ID() {
							_ = b.gate.Finish(r.Key.ID(), true, true)
						}
					}
				}
			case a2a.EnvA2ARequest:
				var p a2a.A2ARequestPayload
				var req a2a.ExecutionRequest
				if env.ParsePayload(&p) != nil || json.Unmarshal(p.Body, &req) != nil {
					return errors.New("invalid execution envelope")
				}
				key := ledger.Key{ConversationID: req.ConversationID, StepID: req.StepID, Nonce: req.ExecutionNonce}
				if !key.Valid() || len(env.ID) > 128 || env.ID == "" {
					return errors.New("invalid execution generation")
				}
				if p.Method != "message/send" || p.Capability != "codex" && p.Capability != "opencode" || len(req.Attachments) > 0 || req.Model == "" || req.ModelLimits == nil || req.ModelLimits.MaxOutputTokens < 1 || req.ModelLimits.MaxOutputTokens > 64000 {
					if err = b.send(ws, a2a.EnvA2AResponse, env.ID, a2a.A2AResponsePayload{Status: 400}); err != nil {
						return err
					}
					continue
				}
				if old, ok := b.ledger.Get(key); ok {
					if old.Backend != p.Capability {
						return errors.New("duplicate generation backend mismatch")
					}
					if err = b.send(ws, a2a.EnvA2AResponse, env.ID, a2a.A2AResponsePayload{Status: 200}); err != nil {
						return err
					}
					if old.Result != nil {
						if err = b.result(ws, old); err != nil {
							return err
						}
					}
					continue
				}
				pendingReceipt := false
				for _, record := range b.ledger.Records() {
					if !record.Acknowledged {
						pendingReceipt = true
						break
					}
				}
				if pendingReceipt {
					if err = b.send(ws, a2a.EnvA2AResponse, env.ID, a2a.A2AResponsePayload{Status: 409}); err != nil {
						return err
					}
					continue
				}
				generation, e := b.gate.Acquire(epoch, p.Capability, key.ID())
				if e != nil {
					if err = b.send(ws, a2a.EnvA2AResponse, env.ID, a2a.A2AResponsePayload{Status: 409}); err != nil {
						return err
					}
					continue
				}
				r := ledger.Record{Key: key, InstanceID: b.cfg.Credential.InstanceID, RequestID: env.ID, Backend: p.Capability, Generation: generation}
				if err = b.ledger.Accept(r); err != nil {
					_ = b.gate.Finish(key.ID(), false, false)
					return err
				}
				r, _ = b.ledger.Get(key)
				if err = b.send(ws, a2a.EnvA2AResponse, env.ID, a2a.A2AResponsePayload{Status: 200}); err != nil {
					_ = b.ledger.Finish(key, a2a.ExecutionResult{StepID: key.StepID, Status: "failed", ErrorCode: "acceptance_ack_lost"})
					return err
				}
				if req.Headers == nil {
					req.Headers = map[string]string{}
				}
				for k, v := range p.Headers {
					req.Headers[k] = v
				}
				task, stopTask := context.WithTimeout(ctx, 30*time.Minute)
				taskCancel = stopTask
				active = &r
				jobs.Add(1)
				go func(r ledger.Record, request a2a.ExecutionRequest) {
					defer jobs.Done()
					defer stopTask()
					out := b.execute(task, request, r.Backend, r.Generation, func(event a2a.A2AStreamEventPayload) error {
						event.ConversationID = r.ConversationID
						event.StepID = r.StepID
						return b.send(ws, a2a.EnvA2AStreamEvent, r.RequestID, event)
					})
					out.Result.StepID = r.StepID
					out.Result = redactResult(out.Result, request, b.cfg.Credential)
					if task.Err() != nil {
						out.Result.Status = "cancelled"
						out.Result.ErrorCode = "execution_cancelled"
					}
					if !out.Clean || !out.Integrity {
						out.Result.Status = "failed"
						out.Result.ErrorCode = "cleanup_or_integrity_failed"
						_ = b.gate.Finish(r.Key.ID(), out.Clean, out.Integrity)
					}
					e := b.ledger.Finish(r.Key, out.Result)
					if e == nil {
						saved, _ := b.ledger.Get(r.Key)
						e = b.result(ws, saved)
					}
					finished <- e
				}(r, req)
			}
		}
	}
}

// Even a backend error must not echo known credentials into the terminal
// record. Adapters additionally redact their own per-task loopback token.
func redactResult(result a2a.ExecutionResult, request a2a.ExecutionRequest, credential vault.Credential) a2a.ExecutionResult {
	secrets := []string{request.ArtifactToken, credential.Token, credential.PrivateKey}
	for key, value := range request.Headers {
		if strings.EqualFold(key, "x-llm-proxy-key") || strings.EqualFold(key, "authorization") {
			secrets = append(secrets, value)
		}
	}
	raw, _ := json.Marshal(result)
	text := string(raw)
	for _, secret := range secrets {
		if secret != "" {
			encoded, _ := json.Marshal(secret)
			text = strings.ReplaceAll(text, string(encoded[1:len(encoded)-1]), "[redacted]")
		}
	}
	var out a2a.ExecutionResult
	if json.Unmarshal([]byte(text), &out) != nil {
		return a2a.ExecutionResult{StepID: result.StepID, Status: "failed", ErrorCode: "invalid_result"}
	}
	return out
}
