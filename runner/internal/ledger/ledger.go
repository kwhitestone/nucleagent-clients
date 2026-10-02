// Package ledger stores task generations, never execution requests or keys.
// The caller holds the application-wide platform lock for the store lifetime.
package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/nucleagent/nucleagent-shared/a2a"
	"nucleagent-desktop-runner/internal/platform"
)

type Key struct {
	ConversationID uint   `json:"conversationId"`
	StepID         string `json:"stepId"`
	Nonce          string `json:"executionNonce"`
}

func (k Key) ID() string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s\x00%s", k.ConversationID, k.StepID, k.Nonce)))
	return hex.EncodeToString(h[:])
}
func (k Key) Valid() bool {
	return k.ConversationID > 0 && len(k.StepID) > 0 && len(k.StepID) <= 128 && len(k.Nonce) > 0 && len(k.Nonce) <= 128
}

type Record struct {
	Key
	InstanceID   string               `json:"instanceId"`
	RequestID    string               `json:"requestId"`
	Backend      string               `json:"backend"`
	Generation   string               `json:"generation"`
	StartedAt    time.Time            `json:"startedAt"`
	EndedAt      *time.Time           `json:"endedAt,omitempty"`
	Result       *a2a.ExecutionResult `json:"result,omitempty"`
	Acknowledged bool                 `json:"acknowledged"`
}
type Store struct {
	mu             sync.Mutex
	root, instance string
	records        map[string]Record
}

const maxRecord = 2 << 20
const maxRecords = 10000 // Fail closed; never discard a nonce fence silently.

func Open(root, instance string) (*Store, error) {
	if !filepath.IsAbs(root) || instance == "" {
		return nil, errors.New("invalid ledger identity")
	}
	if err := platform.PrivateDirectory(root); err != nil {
		return nil, err
	}
	s := &Store{root: root, instance: instance, records: make(map[string]Record)}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		if len(s.records) >= maxRecords || !entry.Type().IsRegular() {
			return nil, errors.New("unsafe task ledger")
		}
		f, err := os.Open(filepath.Join(root, entry.Name()))
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(io.LimitReader(f, maxRecord+1))
		closeErr := f.Close()
		var r Record
		if err != nil || closeErr != nil || len(data) > maxRecord || json.Unmarshal(data, &r) != nil || !r.Key.Valid() || r.InstanceID != instance || r.Key.ID()+".json" != entry.Name() || r.Backend != "codex" && r.Backend != "opencode" || r.Generation == "" || r.RequestID == "" || r.Acknowledged && r.Result == nil {
			return nil, errors.New("invalid task ledger")
		}
		if r.Result != nil && (r.Result.StepID != r.StepID || !terminal(r.Result.Status)) {
			return nil, errors.New("invalid terminal ledger")
		}
		s.records[r.Key.ID()] = r
	}
	return s, nil
}
func clone(r Record) Record {
	raw, _ := json.Marshal(r)
	var out Record
	_ = json.Unmarshal(raw, &out)
	return out
}
func terminal(s string) bool { return s == "completed" || s == "failed" || s == "cancelled" }
func (s *Store) save(r Record) error {
	data, err := json.Marshal(r)
	if err != nil || len(data) > maxRecord {
		return errors.New("task record exceeds bounds")
	}
	f, err := os.CreateTemp(s.root, ".pending-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = publish(f.Name(), filepath.Join(s.root, r.Key.ID()+".json")); err != nil {
		return err
	}
	s.records[r.Key.ID()] = clone(r)
	return nil
}
func (s *Store) Get(k Key) (Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[k.ID()]
	return clone(r), ok
}

// Accept must be durable before the network acceptance ACK or worker launch.
func (s *Store) Accept(r Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !r.Key.Valid() || r.InstanceID != s.instance || r.RequestID == "" || len(r.RequestID) > 128 || r.Generation == "" || r.Backend != "codex" && r.Backend != "opencode" || r.Result != nil || r.Acknowledged {
		return errors.New("invalid task acceptance")
	}
	if _, ok := s.records[r.Key.ID()]; ok {
		return errors.New("duplicate task generation")
	}
	if len(s.records) >= maxRecords {
		return errors.New("task ledger full")
	}
	r.StartedAt = time.Now().UTC()
	return s.save(r)
}
func (s *Store) Finish(k Key, result a2a.ExecutionResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[k.ID()]
	if !ok || r.Result != nil || result.StepID != k.StepID || !terminal(result.Status) {
		return errors.New("invalid terminal transition")
	}
	now := time.Now().UTC()
	r.EndedAt = &now
	r.Result = &result
	return s.save(r)
}

// Ack requires the exact generation and original request correlation.
// ACKs without the exact nonce are rejected by the bridge.
func (s *Store) Ack(k Key, requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[k.ID()]
	if !ok || r.Result == nil || r.RequestID != requestID {
		return errors.New("stale terminal acknowledgement")
	}
	r.Acknowledged = true
	return s.save(r)
}
func (s *Store) Records() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Record, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, clone(r))
	}
	return out
}

// Recovery never resumes a worker or restores keys. Cleanup must precede this.
func (s *Store) Recover() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.records {
		if r.Result == nil {
			now := time.Now().UTC()
			r.EndedAt = &now
			r.Result = &a2a.ExecutionResult{StepID: r.StepID, Status: "failed", ErrorCode: "executor_interrupted", Error: "Executor interrupted; task was not replayed"}
			if err := s.save(r); err != nil {
				return err
			}
		}
	}
	return nil
}

// Unsafe is a persistent admission fence. Pending results may still be replayed,
// but a reconnect must not clear a cleanup or integrity failure.
func (s *Store) Unsafe() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.records {
		if r.Result != nil && r.Result.ErrorCode == "cleanup_or_integrity_failed" {
			return true
		}
	}
	return false
}
