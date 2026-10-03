// Package adapter contains bounded native CLI protocol drivers.
package adapter

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"

	"nucleagent-desktop-runner/internal/platform"
)

type rpcMessage struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  json.RawMessage `json:"error,omitempty"`
}

// Preserve the response for credential-free diagnostics; Error deliberately
// omits remote text because production responses may contain sensitive data.
type protocolError struct {
	method   string
	response json.RawMessage
}

func (e *protocolError) Error() string { return "CLI rejected protocol request: " + e.method }

type rpc struct {
	p        *platform.Process
	mu       sync.Mutex
	next     int
	messages chan rpcMessage
	done     chan struct{}
	onNotify func(rpcMessage) error
}

func newRPC(p *platform.Process) *rpc {
	r := &rpc{p: p, messages: make(chan rpcMessage, 128), done: make(chan struct{})}
	go func() { _, _ = io.Copy(io.Discard, p.Stderr) }() // Raw CLI diagnostics may contain secrets.
	go func() {
		defer close(r.messages)
		scanner := bufio.NewScanner(p.Stdout)
		scanner.Buffer(make([]byte, 4096), 4<<20)
		for scanner.Scan() {
			var msg rpcMessage
			if json.Unmarshal(scanner.Bytes(), &msg) != nil {
				return
			}
			select {
			case r.messages <- msg:
			case <-r.done:
				return
			}
		}
	}()
	return r
}
func (r *rpc) close() error { close(r.done); return r.p.Close() }
func (r *rpc) send(value any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return json.NewEncoder(r.p.Stdin).Encode(value)
}
func (r *rpc) notify(method string, params any) error {
	return r.send(map[string]any{"method": method, "params": params})
}

// Calls are serialized by the adapter; requests from the CLI are denied rather
// than auto-approved. No raw remote error message crosses the diagnostic API.
func (r *rpc) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	r.next++
	id := r.next
	if err := r.send(map[string]any{"id": id, "method": method, "params": params}); err != nil {
		return nil, err
	}
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case msg, ok := <-r.messages:
			if !ok {
				return nil, errors.New("CLI protocol stream closed")
			}
			if msg.Method != "" && len(msg.ID) > 0 {
				if err := r.send(map[string]any{"id": msg.ID, "error": map[string]any{"code": -32601, "message": "interactive requests unsupported"}}); err != nil {
					return nil, err
				}
				continue
			}
			var reply int
			if json.Unmarshal(msg.ID, &reply) != nil || reply != id {
				if msg.Method != "" && r.onNotify != nil {
					if err := r.onNotify(msg); err != nil {
						return nil, err
					}
				}
				continue
			}
			if len(msg.Error) > 0 && string(msg.Error) != "null" {
				return nil, &protocolError{method: method, response: append(json.RawMessage(nil), msg.Error...)}
			}
			return msg.Result, nil
		}
	}
}
