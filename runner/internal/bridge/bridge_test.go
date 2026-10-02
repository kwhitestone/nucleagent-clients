package bridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/nucleagent/nucleagent-shared/a2a"
	"github.com/nucleagent/nucleagent-shared/llm"
	"nucleagent-desktop-runner/internal/ledger"
	"nucleagent-desktop-runner/internal/vault"
)

type fixture struct {
	b      *Bridge
	ledger *ledger.Store
	core   *websocket.Conn
	done   chan error
}

func setup(t *testing.T, run Execute) *fixture {
	t.Helper()
	l, err := ledger.Open(t.TempDir(), "pc-instance")
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(Config{Credential: vault.Credential{DeviceID: "pc-device", InstanceID: "pc-instance"}, OS: "fixture", Arch: "fixture", Backends: []a2a.PCBackendAdmission{{ID: "codex", Generation: "gen", CLIVersion: "version", AdapterVersion: "1", ProtocolVersion: "1"}}}, l, run)
	if err != nil {
		t.Fatal(err)
	}
	connected := make(chan *websocket.Conn, 1)
	up := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, e := up.Upgrade(w, r, nil)
		if e == nil {
			connected <- ws
		}
	}))
	t.Cleanup(server.Close)
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	core := <-connected
	ctx, cancel := context.WithCancel(context.Background())
	f := &fixture{b: b, ledger: l, core: core, done: make(chan error, 1)}
	go func() { f.done <- b.Serve(ctx, ws) }()
	t.Cleanup(func() {
		cancel()
		core.Close()
		select {
		case <-f.done:
		case <-time.After(3 * time.Second):
			t.Error("bridge did not drain")
		}
	})
	return f
}
func (f *fixture) read(t *testing.T, kind string) *a2a.Envelope {
	t.Helper()
	f.core.SetReadDeadline(time.Now().Add(3 * time.Second))
	var e a2a.Envelope
	if err := f.core.ReadJSON(&e); err != nil {
		t.Fatal(err)
	}
	if e.Type != kind {
		t.Fatalf("got %s, want %s", e.Type, kind)
	}
	return &e
}
func (f *fixture) send(t *testing.T, kind, request string, payload any) {
	t.Helper()
	e, err := a2a.NewEnvelopeWithRequest(time.Now().UnixMilli(), kind, request, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.core.WriteJSON(e); err != nil {
		t.Fatal(err)
	}
}
func (f *fixture) handshake(t *testing.T, contract string) {
	t.Helper()
	e := f.read(t, a2a.EnvHandshake)
	var p a2a.HandshakePayload
	if err := e.ParsePayload(&p); err != nil {
		t.Fatal(err)
	}
	if p.PC == nil || p.PC.State != "paused" || p.Capacity.MaxConcurrency != 1 || p.Runtime != nil {
		t.Fatal("invalid cold handshake")
	}
	f.send(t, a2a.EnvHandshakeAck, "", a2a.HandshakeAckPayload{Status: "ok", PCContract: contract, AdmissionRevision: p.PC.Revision})
}
func (f *fixture) enable(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := f.b.SetEnabled(ctx, true, true); err != nil {
		t.Fatal(err)
	}
	e := f.read(t, a2a.EnvPCAdmission)
	var p a2a.PCAdmission
	_ = e.ParsePayload(&p)
	if p.State != "ready" {
		t.Fatalf("state %s", p.State)
	}
	f.send(t, a2a.EnvPCAdmissionAck, "", a2a.PCAdmissionAck{Status: "ok", Revision: p.Revision})
	for deadline := time.Now().Add(time.Second); f.b.Snapshot().State != "ready"; {
		if time.Now().After(deadline) {
			t.Fatal("admission never ready")
		}
		time.Sleep(time.Millisecond)
	}
}
func (f *fixture) request(t *testing.T, nonce string) string {
	t.Helper()
	req := a2a.ExecutionRequest{ConversationID: 1, StepID: "step", ExecutionNonce: nonce, Model: "fixture", ModelLimits: &llm.ModelLimits{MaxOutputTokens: 32}, Input: "fixture"}
	raw, _ := json.Marshal(req)
	e, _ := a2a.NewEnvelopeNow(a2a.EnvA2ARequest, a2a.A2ARequestPayload{Method: "message/send", Capability: "codex", Body: raw})
	if err := f.core.WriteJSON(e); err != nil {
		t.Fatal(err)
	}
	return e.ID
}
func TestOldCoreCannotEnable(t *testing.T) {
	f := setup(t, func(context.Context, a2a.ExecutionRequest, string, string, func(a2a.A2AStreamEventPayload) error) Outcome {
		t.Error("executed")
		return Outcome{}
	})
	f.handshake(t, "")
	select {
	case err := <-f.done:
		if err == nil {
			t.Fatal("old contract accepted")
		}
		f.done <- err
	case <-time.After(time.Second):
		t.Fatal("old core not rejected")
	}
	if f.b.Snapshot().State == "ready" {
		t.Fatal("admission opened")
	}
}
func TestDuplicateAndTerminalAckNeverRepeatExecution(t *testing.T) {
	var runs atomic.Int32
	f := setup(t, func(ctx context.Context, req a2a.ExecutionRequest, backend, generation string, emit func(a2a.A2AStreamEventPayload) error) Outcome {
		runs.Add(1)
		return Outcome{Result: a2a.ExecutionResult{Status: "completed", Output: "done"}, Clean: true, Integrity: true}
	})
	f.handshake(t, a2a.PCContractV1)
	f.request(t, "before-consent")
	e := f.read(t, a2a.EnvA2AResponse)
	var response a2a.A2AResponsePayload
	_ = e.ParsePayload(&response)
	if response.Status != 409 {
		t.Fatal("accepted without consent")
	}
	f.enable(t)
	request := f.request(t, "nonce")
	f.read(t, a2a.EnvA2AResponse)
	f.read(t, a2a.EnvA2ATaskResult)
	f.request(t, "nonce")
	f.read(t, a2a.EnvA2AResponse)
	f.read(t, a2a.EnvA2ATaskResult)
	if runs.Load() != 1 {
		t.Fatal("duplicate execution")
	}
	f.send(t, a2a.EnvA2ATaskResultAck, "foreign", a2a.A2ATaskResultAckPayload{ConversationID: 1, StepID: "step", ExecutionNonce: "nonce", Status: "accepted"})
	f.request(t, "different")
	e = f.read(t, a2a.EnvA2AResponse)
	_ = e.ParsePayload(&response)
	if response.Status != 409 {
		t.Fatal("stale ACK released capacity")
	}
	for _, nonce := range []string{"", "wrong-nonce"} {
		f.send(t, a2a.EnvA2ATaskResultAck, request, a2a.A2ATaskResultAckPayload{ConversationID: 1, StepID: "step", ExecutionNonce: nonce, Status: "accepted"})
		f.request(t, "still-blocked")
		_ = f.read(t, a2a.EnvA2AResponse).ParsePayload(&response)
		if response.Status != 409 {
			t.Fatal("missing/wrong nonce released capacity")
		}
	}
	f.send(t, a2a.EnvA2ATaskResultAck, request, a2a.A2ATaskResultAckPayload{ConversationID: 1, StepID: "step", ExecutionNonce: "nonce", Status: "accepted"})
	deadline := time.Now().Add(time.Second)
	for f.b.Snapshot().Active != "" {
		if time.Now().After(deadline) {
			t.Fatal("ACK did not release slot")
		}
		time.Sleep(time.Millisecond)
	}
	r, ok := f.ledger.Get(ledger.Key{ConversationID: 1, StepID: "step", Nonce: "nonce"})
	if !ok || !r.Acknowledged {
		t.Fatal("ACK not persisted")
	}
}
func TestDisconnectCancelsAndPersistsBeforeReturn(t *testing.T) {
	started := make(chan struct{})
	cleaned := make(chan struct{})
	f := setup(t, func(ctx context.Context, req a2a.ExecutionRequest, backend, generation string, emit func(a2a.A2AStreamEventPayload) error) Outcome {
		close(started)
		<-ctx.Done()
		close(cleaned)
		return Outcome{Result: a2a.ExecutionResult{Status: "cancelled"}, Clean: true, Integrity: true}
	})
	f.handshake(t, a2a.PCContractV1)
	f.enable(t)
	f.request(t, "nonce")
	f.read(t, a2a.EnvA2AResponse)
	<-started
	f.core.Close()
	select {
	case err := <-f.done:
		f.done <- err
	case <-time.After(2 * time.Second):
		t.Fatal("disconnect did not finish")
	}
	select {
	case <-cleaned:
	default:
		t.Fatal("returned before cleanup")
	}
	r, ok := f.ledger.Get(ledger.Key{ConversationID: 1, StepID: "step", Nonce: "nonce"})
	if !ok || r.Result == nil || r.Result.Status != "cancelled" {
		t.Fatal("terminal not persisted")
	}
}

func TestKnownCredentialsAreRedactedFromTerminalProjection(t *testing.T) {
	request := a2a.ExecutionRequest{ArtifactToken: "artifact-fixture-secret", Headers: map[string]string{"X-LLM-Proxy-Key": "core-fixture-secret"}}
	credential := vault.Credential{Token: "device-fixture-secret", PrivateKey: "private-fixture-secret"}
	result := redactResult(a2a.ExecutionResult{StepID: "step", Status: "failed", Output: "core-fixture-secret device-fixture-secret", Error: "artifact-fixture-secret private-fixture-secret"}, request, credential)
	raw, _ := json.Marshal(result)
	if strings.Contains(string(raw), "fixture-secret") || !strings.Contains(string(raw), "[redacted]") || result.StepID != "step" || result.Status != "failed" {
		t.Fatalf("unsafe terminal projection: %s", raw)
	}
}

func TestCleanupFailureRemainsFencedAfterResultACK(t *testing.T) {
	f := setup(t, func(context.Context, a2a.ExecutionRequest, string, string, func(a2a.A2AStreamEventPayload) error) Outcome {
		return Outcome{Result: a2a.ExecutionResult{Status: "completed"}, Clean: false, Integrity: true}
	})
	f.handshake(t, a2a.PCContractV1)
	f.enable(t)
	request := f.request(t, "nonce")
	f.read(t, a2a.EnvA2AResponse)
	result := f.read(t, a2a.EnvA2ATaskResult)
	var payload a2a.A2ATaskResultPayload
	_ = result.ParsePayload(&payload)
	if payload.Status != "failed" {
		t.Fatal("cleanup failure reported success")
	}
	f.send(t, a2a.EnvA2ATaskResultAck, request, a2a.A2ATaskResultAckPayload{ConversationID: 1, StepID: "step", ExecutionNonce: "nonce", Status: "accepted"})
	f.request(t, "next")
	var response a2a.A2AResponsePayload
	_ = f.read(t, a2a.EnvA2AResponse).ParsePayload(&response)
	if response.Status != 409 {
		t.Fatal("ACK removed cleanup fence")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := f.b.SetEnabled(ctx, true, true); err == nil {
		t.Fatal("failed worker can be re-enabled")
	}
}

func TestStaleCancellationCannotKillNewGeneration(t *testing.T) {
	started := make(chan struct{})
	stopped := make(chan struct{})
	f := setup(t, func(ctx context.Context, _ a2a.ExecutionRequest, _, _ string, _ func(a2a.A2AStreamEventPayload) error) Outcome {
		close(started)
		<-ctx.Done()
		close(stopped)
		return Outcome{Result: a2a.ExecutionResult{Status: "cancelled"}, Clean: true, Integrity: true}
	})
	f.handshake(t, a2a.PCContractV1)
	f.enable(t)
	f.request(t, "nonce")
	f.read(t, a2a.EnvA2AResponse)
	<-started
	f.send(t, a2a.EnvTaskKill, "", a2a.TaskKillPayload{ConversationIDs: []uint{1}, StepID: "step", ExecutionNonce: "old-nonce"})
	// Ping/pong provides an ordering barrier after the stale cancellation.
	f.send(t, a2a.EnvPing, "barrier", a2a.PingPayload{})
	f.read(t, a2a.EnvPong)
	select {
	case <-stopped:
		t.Fatal("stale cancellation killed worker")
	default:
	}
	f.send(t, a2a.EnvTaskKill, "", a2a.TaskKillPayload{ConversationIDs: []uint{1}, StepID: "step", ExecutionNonce: "nonce"})
	var payload a2a.A2ATaskResultPayload
	_ = f.read(t, a2a.EnvA2ATaskResult).ParsePayload(&payload)
	if payload.Status != "cancelled" {
		t.Fatal("current cancellation ignored")
	}
}
