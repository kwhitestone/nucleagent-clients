//go:build windows

package isolation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// Relay exposes only POST /v1/responses. Its upstream is the existing scoped
// LLM proxy, selected by the broker, never by a worker request. Core credentials
// remain in that proxy. The capability is fresh for each task and revoked by Close.
type Relay struct {
	Pipe, Token string
	serverPipe  string
	server      *http.Server
	transport   *http.Transport
	cancel      context.CancelFunc
}

func StartRelay(ctx context.Context, sid string, job windows.Handle, endpoint, upstreamToken string) (*Relay, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.Path != "/v1" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || upstreamToken == "" || job == 0 {
		return nil, errors.New("invalid fixed relay scope")
	}
	packageSID, err := windows.StringToSid(sid)
	if err != nil || !strings.HasPrefix(sid, "S-1-15-2-") || packageSID.SubAuthorityCount() != 8 {
		return nil, errors.New("task package SID required")
	}
	owner, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	name := "nucleagent-" + hex.EncodeToString(nonce)
	pipe := `\\.\pipe\LOCAL\` + name
	var sessionID uint32
	if err = windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sessionID); err != nil {
		return nil, err
	}
	serverPipe := fmt.Sprintf(`\\.\pipe\Sessions\%d\AppContainerNamedObjects\%s\%s`, sessionID, sid, name)
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	// Exclude FILE_CREATE_PIPE_INSTANCE (0x4). Generic write would grant it.
	// Owner is needed for broker instance creation; peer checks reject host clients.
	sddl := "D:P(A;;FA;;;" + owner.User.Sid.String() + ")(A;;0x12019b;;;" + sid + ")(A;;RC;;;OW)S:(ML;;NW;;;LW)"
	l, err := winio.ListenPipe(serverPipe, &winio.PipeConfig{SecurityDescriptor: sddl, InputBufferSize: 8192, OutputBufferSize: 8192})
	if err != nil {
		return nil, err
	}
	task, cancel := context.WithCancel(ctx)
	tr := &http.Transport{Proxy: nil, MaxConnsPerHost: 2, ResponseHeaderTimeout: 60 * time.Second}
	p := &Relay{Pipe: pipe, Token: hex.EncodeToString(nonce), serverPipe: serverPipe, transport: tr, cancel: cancel}
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	p.server = &http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return task }}
	p.server.Handler = relayHandler(task, endpoint+"/responses", upstreamToken, p.Token, client)
	go func() {
		_ = p.server.Serve(&relayListener{Listener: l, sid: sid, job: job, slots: make(chan struct{}, 8)})
	}()
	go func() { <-task.Done(); _ = p.server.Close() }()
	return p, nil
}

func (p *Relay) Close() { p.cancel(); _ = p.server.Close(); p.transport.CloseIdleConnections() }

type relayListener struct {
	net.Listener
	sid   string
	job   windows.Handle
	slots chan struct{}
}

type relayConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *relayConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }

func (l *relayListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if verifyRelayPeer(c, l.sid, l.job) == nil {
			select {
			case l.slots <- struct{}{}:
				return &relayConn{Conn: c, release: func() { <-l.slots }}, nil
			default:
			}
		}
		_ = c.Close()
	}
}

func verifyRelayPeer(c net.Conn, sid string, job windows.Handle) error {
	f, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return errors.New("pipe handle missing")
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(windows.Handle(f.Fd()), &pid); err != nil {
		return err
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	var token windows.Token
	if err = windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()
	e, err := InspectToken(token)
	if err != nil {
		return err
	}
	if e.AppContainer != 1 || e.Package != sid || len(e.Capabilities) != 0 {
		return errors.New("foreign relay peer")
	}
	if err = verifyToken(e, sid); err != nil {
		return err
	}
	var inJob int32
	r, _, er := windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob").Call(uintptr(h), uintptr(job), uintptr(unsafe.Pointer(&inJob)))
	if r == 0 {
		return er
	}
	if inJob == 0 {
		return errors.New("relay peer outside task job")
	}
	return nil
}

func relayHandler(task context.Context, fixedURL, upstreamToken, token string, client *http.Client) http.Handler {
	active := make(chan struct{}, 2)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if task.Err() != nil {
			http.Error(w, "task ended", 410)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		if r.Method != "POST" || r.URL.Path != "/v1/responses" || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.IsAbs() || r.Host != "task-broker" || r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" || r.Header.Get("Upgrade") != "" {
			http.Error(w, "route unavailable", 403)
			return
		}
		select {
		case active <- struct{}{}:
			defer func() { <-active }()
		default:
			http.Error(w, "busy", 429)
			return
		}
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
		if err != nil {
			http.Error(w, "request too large", 413)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "POST", fixedURL, bytes.NewReader(b))
		if err != nil {
			http.Error(w, "relay unavailable", 502)
			return
		}
		req.Header.Set("Authorization", "Bearer "+upstreamToken)
		req.Header.Set("Content-Type", "application/json")
		res, err := client.Do(req)
		if err != nil {
			http.Error(w, "relay unavailable", 502)
			return
		}
		defer res.Body.Close()
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			http.Error(w, "upstream rejected", 502)
			return
		}
		w.Header().Set("Content-Type", res.Header.Get("Content-Type"))
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(res.StatusCode)
		buf := make([]byte, 8192)
		for {
			n, er := res.Body.Read(buf)
			if n > 0 {
				if _, err = w.Write(buf[:n]); err != nil {
					return
				}
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
			if er != nil {
				return
			}
		}
	})
}

// DialRelay requests data-write, not generic-write (which includes server-instance
// creation). Identification-level SQOS prevents server impersonation of a worker.
func DialRelay(ctx context.Context, pipe string) (net.Conn, error) {
	if !strings.HasPrefix(pipe, `\\.\pipe\LOCAL\nucleagent-`) {
		return nil, errors.New("invalid relay pipe")
	}
	return winio.DialPipeAccessImpLevel(ctx, pipe, windows.GENERIC_READ|windows.FILE_WRITE_DATA|windows.SYNCHRONIZE, winio.PipeImpLevelIdentification)
}

// StartTaskHTTPRelay runs INSIDE the task AppContainer. Codex's HTTP client
// reaches this same-package listener; its only outbound transport is the pipe.
// This helper is untrusted and receives no upstream proxy credential.
func StartTaskHTTPRelay(ctx context.Context, pipe, token string) (string, func(), error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	tr := &http.Transport{Proxy: nil, MaxConnsPerHost: 2, ResponseHeaderTimeout: 60 * time.Second, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return DialRelay(ctx, pipe) }}
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	h := relayHandler(ctx, "http://task-broker/v1/responses", token, token, client)
	s := &http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != l.Addr().String() {
			http.Error(w, "unauthorized", 401)
			return
		}
		r.Host = "task-broker"
		h.ServeHTTP(w, r)
	})
	go func() { _ = s.Serve(l) }()
	close := func() { _ = s.Close(); tr.CloseIdleConnections() }
	return "http://" + l.Addr().String() + "/v1", close, nil
}
