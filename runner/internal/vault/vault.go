// Package vault protects the long-lived device credential with the current
// native user's OS secret store. Task-scoped Core keys must never enter it.
package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"nucleagent-desktop-runner/internal/platform"
)

type Credential struct {
	DeviceID   string    `json:"deviceId"`
	InstanceID string    `json:"instanceId"`
	Token      string    `json:"token"`
	PrivateKey string    `json:"privateKey"`
	CoreOrigin string    `json:"coreOrigin"`
	Version    uint64    `json:"version"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

type Store struct{ root, service string }

func New(root string) (*Store, error) {
	if err := platform.RequireNativeUser(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(root) {
		return nil, errors.New("absolute credential store root required")
	}
	if err := platform.PrivateDirectory(root); err != nil {
		return nil, err
	}
	hash := sha256.Sum256([]byte(filepath.Clean(root)))
	return &Store{root: root, service: "top.whitestone.nucleagent.device." + hex.EncodeToString(hash[:16])}, nil
}
func (s *Store) Save(c Credential) error {
	if c.DeviceID == "" || c.InstanceID == "" || c.Token == "" || c.PrivateKey == "" || c.CoreOrigin == "" {
		return errors.New("incomplete device credential")
	}
	raw, err := json.Marshal(c)
	if err != nil || len(raw) > 16384 {
		return errors.New("invalid device credential")
	}
	return s.write(raw)
}
func (s *Store) Load() (Credential, error) {
	raw, err := s.read()
	if err != nil {
		return Credential{}, err
	}
	var c Credential
	if len(raw) > 16384 || json.Unmarshal(raw, &c) != nil || c.Token == "" || c.PrivateKey == "" {
		return Credential{}, errors.New("invalid protected device credential")
	}
	return c, nil
}
func (s *Store) Delete() error { return s.remove() }
