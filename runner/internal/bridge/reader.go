package bridge

import (
	"errors"
	"time"

	"github.com/gorilla/websocket"
	"github.com/nucleagent/nucleagent-shared/a2a"
)

type group struct {
	parts   []*a2a.Envelope
	bytes   int
	started time.Time
}
type reader struct {
	ws     *websocket.Conn
	groups map[string]*group
}

func newReader(ws *websocket.Conn) *reader { return &reader{ws: ws, groups: map[string]*group{}} }
func (r *reader) read() (*a2a.Envelope, error) {
	for {
		_ = r.ws.SetReadDeadline(time.Now().Add(45 * time.Second))
		var env a2a.Envelope
		if r.ws.ReadJSON(&env) != nil {
			return nil, errors.New("core connection ended")
		}
		if env.Version != 1 || env.ID == "" {
			return nil, errors.New("invalid envelope")
		}
		for _, g := range r.groups {
			if time.Since(g.started) > 30*time.Second {
				return nil, errors.New("chunk timeout")
			}
		}
		if env.ChunkID == "" {
			return &env, nil
		}
		if env.ChunkTotal < 1 || env.ChunkTotal > 48 || env.ChunkIndex < 0 || env.ChunkIndex >= env.ChunkTotal {
			return nil, errors.New("invalid chunk bounds")
		}
		g := r.groups[env.ChunkID]
		if g == nil {
			if len(r.groups) >= 2 {
				return nil, errors.New("too many chunk groups")
			}
			g = &group{started: time.Now()}
			r.groups[env.ChunkID] = g
		}
		for _, p := range g.parts {
			if p.ChunkIndex == env.ChunkIndex || p.ChunkTotal != env.ChunkTotal || p.Type != env.Type || p.RequestID != env.RequestID || p.Timestamp != env.Timestamp {
				return nil, errors.New("inconsistent chunk group")
			}
		}
		g.bytes += len(env.Payload)
		if g.bytes > 6<<20 {
			return nil, errors.New("chunk payload exceeds bounds")
		}
		g.parts = append(g.parts, &env)
		if len(g.parts) != env.ChunkTotal {
			continue
		}
		all, pending, err := a2a.DecodeEnvelopeFrames(g.parts)
		if err != nil || pending != 0 || len(all) != 1 {
			return nil, errors.New("chunk decode failed")
		}
		delete(r.groups, env.ChunkID)
		return all[0], nil
	}
}
