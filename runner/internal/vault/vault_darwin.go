//go:build darwin

package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os/exec"
	"strings"
	"time"
)

// security's interactive input keeps the secret out of process arguments. The
// service/account are fixed, and the value is base64 without whitespace or
// quoting characters, so it cannot inject another security command. No shell
// parses this input. Keychain remains the authority for access and prompts.
func (s *Store) write(raw []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/security", "-i")
	cmd.Stdin = strings.NewReader("add-generic-password -U -a nucleagent -s " + s.service + " -w " + base64.StdEncoding.EncodeToString(raw) + "\n")
	if err := cmd.Run(); err != nil {
		return errors.New("macOS Keychain write failed")
	}
	actual, err := s.read()
	if err != nil || !bytes.Equal(actual, raw) {
		return errors.New("macOS Keychain write verification failed")
	}
	return nil
}
func (s *Store) read() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/security", "find-generic-password", "-a", "nucleagent", "-s", s.service, "-w").Output()
	if err != nil {
		return nil, errors.New("macOS device credential unavailable")
	}
	if len(out) > 32768 {
		return nil, errors.New("macOS credential exceeds bound")
	}
	value, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	clear(out)
	if err != nil {
		return nil, errors.New("invalid protected credential")
	}
	return value, nil
}
func (s *Store) remove() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "/usr/bin/security", "delete-generic-password", "-a", "nucleagent", "-s", s.service).Run(); err != nil {
		return errors.New("macOS Keychain deletion failed")
	}
	return nil
}
