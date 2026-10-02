package device

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nucleagent/nucleagent-shared/a2a"
	"nucleagent-desktop-runner/internal/vault"
)

func TestRejectUntrustedCoreOrigins(t *testing.T) {
	for _, origin := range []string{"http://core.example", "https://user:secret@core.example", "https://core.example/path", "https://core.example?token=secret", "https://core.example/#fragment", "file:///tmp/core"} {
		if _, err := New(origin); err == nil {
			t.Errorf("accepted %s", origin)
		}
	}
}
func TestBindingProofAndPrivateRegistration(t *testing.T) {
	var public ed25519.PublicKey
	challenge := a2a.PCBindChallenge{ID: "challenge", Nonce: strings.Repeat("n", 64), UserCode: "12345678", ExpiresAt: time.Now().Add(5 * time.Minute)}
	credential := a2a.PCDeviceCredential{DeviceID: "pc-device", InstanceID: "pc-instance", Token: "pcd_" + strings.Repeat("t", 64), Version: 1, ExpiresAt: time.Now().Add(time.Hour)}
	var origin string
	var confirmed atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" || r.Header.Get("X-Executor-Token") != "" {
			t.Error("wrong credential channel")
		}
		var out any
		switch r.URL.Path {
		case a2a.PCNativePath + "/bind/start":
			var in a2a.PCBindStart
			if json.NewDecoder(r.Body).Decode(&in) != nil {
				t.Error("invalid start")
			}
			key, _ := base64.StdEncoding.DecodeString(in.PublicKey)
			public = key
			out = challenge
		case a2a.PCNativePath + "/bind/finish":
			var in a2a.PCBindFinish
			_ = json.NewDecoder(r.Body).Decode(&in)
			sig, _ := base64.StdEncoding.DecodeString(in.Signature)
			if in.ID != challenge.ID || !ed25519.Verify(public, []byte("nucleagent-bind-v1\n"+challenge.ID+"\n"+challenge.Nonce), sig) {
				t.Error("bad proof")
				w.WriteHeader(403)
				return
			}
			if !confirmed.Load() {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			out = credential
		case a2a.PCNativePath + "/register":
			if r.Header.Get("Authorization") != "Bearer "+credential.Token {
				t.Error("missing device auth")
			}
			out = a2a.PCRegistration{DeviceID: credential.DeviceID, InstanceID: credential.InstanceID, PCContract: a2a.PCContractV1, WSURL: "wss" + strings.TrimPrefix(origin, "https") + a2a.PCNativePath + "/ws"}
		default:
			t.Error("unexpected endpoint")
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": out})
	}))
	defer server.Close()
	origin = server.URL
	c, err := New(origin)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.http = server.Client()
	b, err := c.Begin(context.Background(), "fixture", "windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Finish(context.Background(), b); err != ErrPending {
		t.Fatalf("got %v", err)
	}
	confirmed.Store(true)
	v, err := c.Finish(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Register(context.Background(), v); err != nil {
		t.Fatal(err)
	}
	v.CoreOrigin = "https://foreign.example"
	if _, err = c.Register(context.Background(), v); err == nil {
		t.Fatal("cross-origin credential accepted")
	}
}
func TestRegistrationRejectsOffOriginAndLegacyContract(t *testing.T) {
	for _, tc := range []struct{ name, ws, contract string }{{"foreign", "wss://foreign.example" + a2a.PCNativePath + "/ws", a2a.PCContractV1}, {"legacy", "", ""}, {"url-token", "?token=secret", a2a.PCContractV1}} {
		t.Run(tc.name, func(t *testing.T) {
			var origin string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ws := tc.ws
				if ws == "" || strings.HasPrefix(ws, "?") {
					ws = "wss" + strings.TrimPrefix(origin, "https") + a2a.PCNativePath + "/ws" + ws
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": a2a.PCRegistration{DeviceID: "pc-device", InstanceID: "pc-instance", PCContract: tc.contract, WSURL: ws}})
			}))
			defer server.Close()
			origin = server.URL
			c, _ := New(origin)
			c.http = server.Client()
			defer c.Close()
			if _, err := c.Register(context.Background(), vault.Credential{DeviceID: "pc-device", InstanceID: "pc-instance", CoreOrigin: origin, Token: "pcd_fixture"}); err == nil {
				t.Fatal("invalid registration accepted")
			}
		})
	}
}
func TestDeviceErrorsNeverEchoSecretsOrFollowRedirects(t *testing.T) {
	var leaked atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
	defer target.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(307)
		_, _ = w.Write([]byte("fixture-super-secret"))
	}))
	defer server.Close()
	c, _ := New(server.URL)
	c.http.Transport = server.Client().Transport
	defer c.Close()
	_, err := c.Begin(context.Background(), "test", "windows", "amd64")
	if err == nil || strings.Contains(err.Error(), "fixture-super-secret") || leaked.Load() != 0 {
		t.Fatal("unsafe redirect/error")
	}
}
func TestExpiredChallengeNeverCompletes(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	c, _ := New("https://core.example")
	defer c.Close()
	if _, err := c.Finish(context.Background(), &Binding{private: key, Challenge: a2a.PCBindChallenge{ExpiresAt: time.Now().Add(-time.Second)}}); err == nil {
		t.Fatal("expired binding accepted")
	}
}
