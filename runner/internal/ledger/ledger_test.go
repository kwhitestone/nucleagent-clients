package ledger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nucleagent/nucleagent-shared/a2a"
)

func record() Record {
	return Record{Key: Key{ConversationID: 42, StepID: "step", Nonce: "nonce"}, InstanceID: "pc-instance", RequestID: "request", Backend: "codex", Generation: "generation"}
}
func TestDurableAdmissionRecoveryAndGenerationFence(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root, "pc-instance")
	if err != nil {
		t.Fatal(err)
	}
	r := record()
	if err = s.Accept(r); err != nil {
		t.Fatal(err)
	}
	if err = s.Accept(r); err == nil {
		t.Fatal("duplicate admitted")
	}
	s, err = Open(root, "pc-instance")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Recover(); err != nil {
		t.Fatal(err)
	}
	saved, ok := s.Get(r.Key)
	if !ok || saved.Result == nil || saved.Result.Status != "failed" || saved.Result.ErrorCode != "executor_interrupted" {
		t.Fatalf("bad recovery: %+v", saved)
	}
	if err = s.Finish(r.Key, a2a.ExecutionResult{StepID: r.StepID, Status: "completed"}); err == nil {
		t.Fatal("terminal overwritten")
	}
	if err = s.Ack(r.Key, "old-request"); err == nil {
		t.Fatal("stale ACK accepted")
	}
	wrong := r.Key
	wrong.Nonce = "next"
	if err = s.Ack(wrong, r.RequestID); err == nil {
		t.Fatal("wrong nonce ACK accepted")
	}
	if err = s.Ack(r.Key, r.RequestID); err != nil {
		t.Fatal(err)
	}
	s, err = Open(root, "pc-instance")
	if err != nil {
		t.Fatal(err)
	}
	saved, _ = s.Get(r.Key)
	if !saved.Acknowledged {
		t.Fatal("ACK not durable")
	}
	if err = s.Accept(r); err == nil {
		t.Fatal("ACK erased nonce fence")
	}
	if _, err = Open(root, "foreign-instance"); err == nil {
		t.Fatal("cross-device recovery allowed")
	}
}
func TestRecordsAreCopiesAndContainNoRequestFields(t *testing.T) {
	s, err := Open(t.TempDir(), "pc-instance")
	if err != nil {
		t.Fatal(err)
	}
	r := record()
	if err = s.Accept(r); err != nil {
		t.Fatal(err)
	}
	if err = s.Finish(r.Key, a2a.ExecutionResult{StepID: r.StepID, Status: "completed", Output: "safe result"}); err != nil {
		t.Fatal(err)
	}
	copy := s.Records()
	copy[0].Result.Output = "mutated"
	got, _ := s.Get(r.Key)
	if got.Result.Output != "safe result" {
		t.Fatal("mutable ledger exposed")
	}
	data, err := os.ReadFile(filepath.Join(s.root, r.Key.ID()+".json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"headers", "artifactToken", "privateKey", "input", "downloadUrl"} {
		if strings.Contains(string(data), `"`+field+`"`) {
			t.Fatalf("forbidden ledger field %s", field)
		}
	}
}
func TestCorruptAndLinkedRecordsFailClosed(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "bad.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root, "pc-instance"); err == nil {
		t.Fatal("corrupt ledger accepted")
	}
}
