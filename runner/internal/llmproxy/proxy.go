// Package llmproxy keeps the Core execution key in runner memory. Workers see
// only a random per-task loopback capability, invalidated on task termination.
package llmproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Scope struct {
	CoreOrigin      string
	Key             string
	Model           string
	MaxOutputTokens int
	API             string // responses or chat/completions, fixed by the backend
}

type Proxy struct {
	URL       string
	Token     string
	server    *http.Server
	transport *http.Transport
	cancel    context.CancelFunc
}

func Start(ctx context.Context, scope Scope) (*Proxy, error) {
	u, err := url.Parse(scope.CoreOrigin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || scope.Key == "" || scope.Model == "" || scope.MaxOutputTokens < 1 || scope.MaxOutputTokens > 64000 || scope.API != "responses" && scope.API != "chat/completions" {
		return nil, errors.New("invalid Core proxy scope")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	token := make([]byte, 32)
	if _, err = rand.Read(token); err != nil {
		listener.Close()
		return nil, err
	}
	task, cancel := context.WithCancel(ctx)
	transport := &http.Transport{Proxy: nil, ResponseHeaderTimeout: 60 * time.Second, MaxConnsPerHost: 2}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	p := &Proxy{URL: "http://" + listener.Addr().String() + "/v1", Token: hex.EncodeToString(token), transport: transport, cancel: cancel}
	p.server = &http.Server{ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return task }}
	p.server.Handler = handler(task, scope, p.Token, listener.Addr().String(), client)
	go func() { _ = p.server.Serve(listener) }()
	go func() { <-task.Done(); _ = p.server.Close() }()
	return p, nil
}
func (p *Proxy) Close() { p.cancel(); _ = p.server.Close(); p.transport.CloseIdleConnections() }

func handler(task context.Context, scope Scope, token, host string, client *http.Client) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Browsers/remote webviews must not turn this into a local execution API.
		if r.Host != host || r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" || r.URL.RawQuery != "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if task.Err() != nil {
			http.Error(w, "task ended", http.StatusGone)
			return
		}
		if r.Method != "POST" || r.URL.Path != "/v1/"+scope.API {
			http.Error(w, "route unavailable", http.StatusForbidden)
			return
		}
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
		if err != nil {
			http.Error(w, "request too large", 413)
			return
		}
		var body map[string]json.RawMessage
		var selected string
		if json.Unmarshal(data, &body) != nil || json.Unmarshal(body["model"], &selected) != nil || selected != scope.Model {
			http.Error(w, "model scope mismatch", 400)
			return
		}
		budgetFields := []string{"max_tokens", "max_completion_tokens"}
		defaultField := "max_tokens"
		if scope.API == "responses" {
			budgetFields = []string{"max_output_tokens"}
			defaultField = "max_output_tokens"
		}
		found := false
		for _, field := range budgetFields {
			if value, ok := body[field]; ok {
				found = true
				var requested int
				if json.Unmarshal(value, &requested) != nil || requested < 1 {
					http.Error(w, "invalid token budget", 400)
					return
				}
				if requested > scope.MaxOutputTokens {
					body[field], _ = json.Marshal(scope.MaxOutputTokens)
				}
			}
		}
		if !found {
			body[defaultField], _ = json.Marshal(scope.MaxOutputTokens)
		}
		data, err = json.Marshal(body)
		if err != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(scope.CoreOrigin, "/")+"/api/llm-proxy/v1/"+scope.API, bytes.NewReader(data))
		if err != nil {
			http.Error(w, "proxy unavailable", 502)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-llm-proxy-key", scope.Key)
		res, err := client.Do(req)
		if err != nil {
			http.Error(w, "Core transport unavailable", 502)
			return
		}
		defer res.Body.Close()
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			http.Error(w, "Core request rejected", 502)
			return
		}
		w.Header().Set("Content-Type", res.Header.Get("Content-Type"))
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(res.StatusCode)
		buffer := make([]byte, 8192)
		for {
			n, readErr := res.Body.Read(buffer)
			if n > 0 {
				if _, err = w.Write(buffer[:n]); err != nil {
					return
				}
				if flush, ok := w.(http.Flusher); ok {
					flush.Flush()
				}
			}
			if readErr != nil {
				return
			}
		}
	})
}
