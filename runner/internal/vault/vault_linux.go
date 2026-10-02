//go:build linux

package vault

import "errors"

func (s *Store) write([]byte) error {
	return errors.New("device credentials require a supported native OS")
}
func (s *Store) read() ([]byte, error) {
	return nil, errors.New("device credentials require a supported native OS")
}
func (s *Store) remove() error { return errors.New("device credentials require a supported native OS") }
