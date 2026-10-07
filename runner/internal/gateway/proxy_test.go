package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestScopeAndSecretSeparation(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		// Kong (PREPROD/PROD) answers 403 to any Bearer: the key must travel
		// only as X-Api-Key, and nothing must reach a Core llm-proxy route.
		if r.Header.Get("X-Api-Key") != "test-core-secret" || r.Header.Get("Authorization") != "" || r.Header.Get("x-llm-proxy-key") != "" {
			t.Error("credential separation failed")
		}
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil || body["max_output_tokens"] != float64(77) || r.URL.Path != "/v1/responses" {
			t.Error("scope/budget not applied")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: fixture\n\n")
	}))
	defer upstream.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := handler(ctx, Scope{GatewayBase: upstream.URL + "/v1", Key: "test-core-secret", Model: "fixed", MaxOutputTokens: 77, API: "responses"}, "local-token", "127.0.0.1:3456", upstream.Client())
	for _, test := range []struct {
		name, host, origin, auth, body, path string
		status                               int
	}{
		{"valid", "127.0.0.1:3456", "", "Bearer local-token", `{"model":"fixed","max_output_tokens":999}`, "/v1/responses", 200},
		{"foreign host", "evil.example", "", "Bearer local-token", `{"model":"fixed"}`, "/v1/responses", 401},
		{"webview origin", "127.0.0.1:3456", "https://hub.example", "Bearer local-token", `{"model":"fixed"}`, "/v1/responses", 401},
		{"wrong key", "127.0.0.1:3456", "", "Bearer test-core-secret", `{"model":"fixed"}`, "/v1/responses", 401},
		{"wrong model", "127.0.0.1:3456", "", "Bearer local-token", `{"model":"other"}`, "/v1/responses", 400},
		{"wrong route", "127.0.0.1:3456", "", "Bearer local-token", `{"model":"fixed"}`, "/v1/chat/completions", 403},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", test.path, strings.NewReader(test.body))
			req.Host = test.host
			req.Header.Set("Authorization", test.auth)
			req.Header.Set("Origin", test.origin)
			out := httptest.NewRecorder()
			h.ServeHTTP(out, req)
			if out.Code != test.status {
				t.Fatalf("got %d expected %d", out.Code, test.status)
			}
			if strings.Contains(out.Body.String(), "test-core-secret") {
				t.Fatal("Core key leaked")
			}
		})
	}
	if calls.Load() != 1 {
		t.Fatal("unauthorized request reached upstream")
	}
	cancel()
	req := httptest.NewRequest("POST", "/v1/responses", strings.NewReader(`{"model":"fixed"}`))
	req.Host = "127.0.0.1:3456"
	req.Header.Set("Authorization", "Bearer local-token")
	out := httptest.NewRecorder()
	h.ServeHTTP(out, req)
	if out.Code != 410 {
		t.Fatal("expired capability accepted")
	}
}

// Regression (T11): a private-device task without a gateway base or minted key
// fails explicitly; it never falls back to a Core relay or a fixed key.
func TestStartRequiresGatewayBaseAndMintedKey(t *testing.T) {
	ctx := context.Background()
	scope := Scope{GatewayBase: "https://gateway.example/v1", Key: "minted", Model: "fixed", MaxOutputTokens: 8, API: "responses"}
	missingBase := scope
	missingBase.GatewayBase = " "
	if _, err := Start(ctx, missingBase); !errors.Is(err, ErrGatewayUnconfigured) {
		t.Fatalf("missing gateway base: %v", err)
	}
	missingKey := scope
	missingKey.Key = ""
	if _, err := Start(ctx, missingKey); !errors.Is(err, ErrGatewayKeyMissing) {
		t.Fatalf("missing key: %v", err)
	}
	for _, base := range []string{"http://gateway.example/v1", "https://user:pw@gateway.example/v1", "https://gateway.example/v1?k=1"} {
		bad := scope
		bad.GatewayBase = base
		if _, err := Start(ctx, bad); err == nil {
			t.Fatalf("unsafe gateway base accepted: %s", base)
		}
	}
	p, err := Start(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	p.Close()
}
