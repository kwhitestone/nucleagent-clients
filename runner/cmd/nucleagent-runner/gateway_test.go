package main

import (
	"context"
	"testing"

	"nucleagent-desktop-runner/internal/gateway"
)

// Regression (T11): Core without GATEWAY_PUBLIC_URL sends no gateway base; the
// task result must say so instead of a generic native_execution_failed.
func TestGatewayErrorCode(t *testing.T) {
	scope := gateway.Scope{GatewayBase: "https://gateway.example/v1", Key: "minted", Model: "m", MaxOutputTokens: 8, API: "responses"}
	for want, mutate := range map[string]func(*gateway.Scope){
		"gateway_unconfigured":  func(s *gateway.Scope) { s.GatewayBase = "" },
		"gateway_key_missing":   func(s *gateway.Scope) { s.Key = "" },
		"gateway_scope_invalid": func(s *gateway.Scope) { s.GatewayBase = "http://gateway.example/v1" },
	} {
		s := scope
		mutate(&s)
		_, err := gateway.Start(context.Background(), s)
		if got := gatewayErrorCode(err); got != want {
			t.Fatalf("got %s want %s (%v)", got, want, err)
		}
	}
}
