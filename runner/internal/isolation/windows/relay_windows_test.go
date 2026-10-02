//go:build windows

package isolation

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func TestRelayFixedUpstream(t *testing.T) {
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.RequestURI() != "/v1/responses" || r.Header.Get("Authorization") != "Bearer upstream" || r.Header.Get("X-Forwarded-Host") != "" || r.Header.Get("Cookie") != "" {
			t.Error("upstream scope changed")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: ok\n\n")
	}))
	defer up.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := relayHandler(ctx, up.URL+"/v1/responses", "upstream", "task", up.Client())
	for _, tc := range []struct {
		name, method, path, token, host string
		want                            int
	}{
		{"valid", "POST", "/v1/responses", "task", "task-broker", 200},
		{"wrong token", "POST", "/v1/responses", "foreign", "task-broker", 401},
		{"connect", "CONNECT", "/v1/responses", "task", "task-broker", 403},
		{"absolute URL", "POST", "http://attacker.invalid/v1/responses", "task", "task-broker", 403},
		{"query", "POST", "/v1/responses?url=http://attacker.invalid", "task", "task-broker", 403},
		{"escape", "POST", "/v1/../admin", "task", "task-broker", 403},
		{"encoded path", "POST", "/v1/%72esponses", "task", "task-broker", 403},
		{"arbitrary route", "POST", "/v1/models", "task", "task-broker", 403},
		{"host", "POST", "/v1/responses", "task", "attacker.invalid", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{"model":"fixture"}`))
			r.Host = tc.host
			r.Header.Set("Authorization", "Bearer "+tc.token)
			r.Header.Set("X-Forwarded-Host", "attacker.invalid")
			r.Header.Set("Cookie", "host-secret")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status %d expected %d", w.Code, tc.want)
			}
			if tc.want == 200 && w.Body.String() != "data: ok\n\n" {
				t.Fatal("stream corrupted")
			}
		})
	}
	for _, header := range []string{"Origin", "Sec-Fetch-Site", "Upgrade"} {
		r := httptest.NewRequest("POST", "/v1/responses", nil)
		r.Host = "task-broker"
		r.Header.Set("Authorization", "Bearer task")
		r.Header.Set(header, "untrusted")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("accepted %s", header)
		}
	}
	r := httptest.NewRequest("POST", "/v1/responses", strings.NewReader(strings.Repeat("x", (4<<20)+1)))
	r.Host = "task-broker"
	r.Header.Set("Authorization", "Bearer task")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatal("unbounded input")
	}
	cancel()
	r = httptest.NewRequest("POST", "/v1/responses", nil)
	r.Host = "task-broker"
	r.Header.Set("Authorization", "Bearer task")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 410 {
		t.Fatal("revoked capability accepted")
	}
	if calls.Load() != 1 {
		t.Fatalf("rejected requests reached upstream: %d", calls.Load())
	}
}

func TestRelayRejectsHostEvenWithTaskToken(t *testing.T) {
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer up.Close()
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(job)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, err := StartRelay(ctx, "S-1-15-2-1-2-3-4-5-6-7", job, up.URL+"/v1", "upstream")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	tr := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return winio.DialPipeAccess(ctx, p.serverPipe, windows.GENERIC_READ|windows.FILE_WRITE_DATA|windows.SYNCHRONIZE)
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "POST", "http://task-broker/v1/responses", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	res, err := client.Do(req)
	if err == nil {
		res.Body.Close()
		t.Fatal("host peer accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("host request reached upstream")
	}
}

func TestRelayDoesNotFollowRedirect(t *testing.T) {
	var leaks atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaks.Add(1) }))
	defer other.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, 307) }))
	defer up.Close()
	client := up.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	h := relayHandler(context.Background(), up.URL+"/v1/responses", "upstream", "task", client)
	req := httptest.NewRequest("POST", "/v1/responses", strings.NewReader(`{}`))
	req.Host = "task-broker"
	req.Header.Set("Authorization", "Bearer task")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 502 || leaks.Load() != 0 {
		t.Fatal("redirect escaped fixed scope")
	}
}

func TestRelayRejectsUnscopedStart(t *testing.T) {
	for _, sid := range []string{"", "S-1-1-0", "S-1-15-2-1"} {
		if p, err := StartRelay(context.Background(), sid, 1, "http://127.0.0.1:1234/v1", "test"); err == nil {
			p.Close()
			t.Fatal("broad SID accepted")
		}
	}
	for _, url := range []string{"http://example.com/v1", "http://127.0.0.1:1234/v1?target=elsewhere", "http://user@127.0.0.1:1234/v1"} {
		if p, err := StartRelay(context.Background(), "S-1-15-2-1-2-3-4-5-6-7", 1, url, "test"); err == nil {
			p.Close()
			t.Fatal("arbitrary scope accepted")
		}
	}
}
