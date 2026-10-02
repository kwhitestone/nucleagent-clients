//go:build darwin || linux

package ledger

import (
	"errors"
	"os"
	"path/filepath"
)

func publish(staged, destination string) error {
	if err := os.Rename(staged, destination); err != nil {
		return err
	}
	// Persist the renamed directory entry before acknowledging admission.
	directory, err := os.Open(filepath.Dir(destination))
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
