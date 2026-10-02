// Package admission owns local capacity and negotiated private-device state.
// A ready backend is cold-startable, never a claim that a process is warm.
package admission

import (
	"errors"
	"sync"
)

const Contract = "private-device-admission-v1"

type Snapshot struct {
	State      string            `json:"state"`
	Revision   uint64            `json:"revision"`
	Negotiated bool              `json:"negotiated"`
	Active     string            `json:"active,omitempty"`
	Backends   map[string]string `json:"backends"`
}

type Gate struct {
	mu         sync.Mutex
	epoch      uint64
	revision   uint64
	ack        uint64
	enabled    bool
	negotiated bool
	active     string
	failed     bool
	backends   map[string]string
}

func New() *Gate { return &Gate{backends: make(map[string]string)} }

// Connect invalidates every ACK from the previous socket and starts paused.
func (g *Gate) Connect() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.epoch++
	g.revision = 1
	g.ack = 0
	g.enabled = false
	g.negotiated = false
	return g.epoch
}
func (g *Gate) Negotiate(epoch uint64, contract string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if epoch != g.epoch || contract != Contract {
		return errors.New("private device contract not acknowledged")
	}
	g.negotiated = true
	return nil
}
func (g *Gate) Disconnect(epoch uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if epoch == g.epoch {
		g.negotiated = false
		g.enabled = false
		g.ack = 0
	}
}

// SetBackend runs only after verified installation/probe, or after drift.
// Changes close admission until a fresh revision has been acknowledged.
func (g *Gate) SetBackend(backend, generation string) error {
	if backend != "codex" && backend != "opencode" {
		return errors.New("unsupported backend")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active != "" {
		return errors.New("backend changes require drain")
	}
	if generation == "" {
		delete(g.backends, backend)
	} else {
		g.backends[backend] = generation
	}
	g.revision++
	g.ack = 0
	return nil
}
func (g *Gate) Enable(consent bool) (uint64, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !consent || !g.negotiated || g.failed || len(g.backends) == 0 {
		return 0, errors.New("consent, negotiated identity and a verified backend are required")
	}
	g.revision++
	g.enabled = true
	g.ack = 0
	return g.revision, nil
}
func (g *Gate) Pause() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.enabled = false
	g.ack = 0
	g.revision++
	return g.revision
}
func (g *Gate) Ack(epoch, revision uint64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.negotiated || epoch != g.epoch || revision != g.revision || revision == 0 {
		return errors.New("stale admission acknowledgement")
	}
	g.ack = revision
	return nil
}
func (g *Gate) Acquire(epoch uint64, backend, run string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if run == "" || epoch != g.epoch || !g.negotiated || !g.enabled || g.failed || g.ack != g.revision {
		return "", errors.New("admission closed")
	}
	generation, ok := g.backends[backend]
	if !ok {
		return "", errors.New("backend unavailable")
	}
	if g.active != "" {
		return "", errors.New("executor capacity full")
	}
	g.active = run
	return generation, nil
}

// Finish may only run after the complete worker tree exits and post-task
// integrity succeeds. Cleanup failure leaves the occupied slot fenced.
func (g *Gate) Finish(run string, clean, integrity bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if run == "" || g.active != run {
		return errors.New("execution generation mismatch")
	}
	if !clean || !integrity {
		g.enabled = false
		g.failed = true
		g.ack = 0
		g.revision++
		return errors.New("cleanup or integrity failed; admission disabled")
	}
	g.active = ""
	return nil
}
func (g *Gate) Snapshot() Snapshot {
	g.mu.Lock()
	defer g.mu.Unlock()
	state := "paused"
	if g.failed || !g.negotiated || len(g.backends) == 0 {
		state = "unavailable"
	} else if g.enabled {
		state = "syncing"
		if g.ack == g.revision {
			state = "ready"
		}
	} else if g.active != "" {
		state = "draining"
	}
	backends := make(map[string]string, len(g.backends))
	for k, v := range g.backends {
		backends[k] = v
	}
	return Snapshot{State: state, Revision: g.revision, Negotiated: g.negotiated, Active: g.active, Backends: backends}
}
