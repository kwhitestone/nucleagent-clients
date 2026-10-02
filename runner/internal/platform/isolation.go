package platform

import (
	"errors"
	"runtime"
)

var ErrIsolationUnavailable = errors.New("isolation_unavailable: Windows AppContainer CLI initialization has not passed admission")

// RequireTaskIsolation is not configurable. Windows must not execute a worker
// through the old Job-only path while the isolated CLI cannot initialize.
// Other platforms retain their existing policy; macOS isolation remains P1.
func RequireTaskIsolation() error {
	if runtime.GOOS == "windows" {
		return ErrIsolationUnavailable
	}
	return nil
}
