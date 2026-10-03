package platform

import "errors"

var ErrIsolationUnavailable = errors.New("isolation_unavailable: Windows task requires Job, private desktop, private ACL and task-local unelevated config")

// Registration checks platform support; Start enforces all per-task prerequisites
// before resuming a worker. Diagnostic isolation packages are never imported.
func RequireTaskIsolation() error { return taskIsolationAvailable() }
