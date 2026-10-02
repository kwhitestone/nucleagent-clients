//go:build windows

package isolation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type childPlan struct{ Root, Outside, Profile, Loopback, RelayPipe, RelayToken string }
type childEvidence struct {
	WindowStation, Desktop, DesktopError                                string
	Token                                                               TokenEvidence
	InJob                                                               bool
	Access                                                              []AccessObservation
	LoopbackOK                                                          bool
	LoopbackError                                                       string
	RelayOK, RelayBadTokenRejected, RelayRouteRejected, TaskHTTPRelayOK bool
	RelayError                                                          string
	RelayInstanceDenied, RelayACLDenied                                 bool
	Descendant                                                          *childEvidence `json:",omitempty"`
}

func ChildProbe(planPath string, descendant ...bool) error {
	b, err := os.ReadFile(planPath)
	if err != nil {
		return err
	}
	var plan childPlan
	if err = json.Unmarshal(b, &plan); err != nil {
		return err
	}
	e := childEvidence{}
	station, _, _ := user32.NewProc("GetProcessWindowStation").Call()
	e.WindowStation, err = userObjectName(station)
	if err != nil {
		e.DesktopError = err.Error()
	}
	desk, _, _ := user32.NewProc("GetThreadDesktop").Call(uintptr(windows.GetCurrentThreadId()))
	e.Desktop, err = userObjectName(desk)
	if err != nil {
		e.DesktopError += err.Error()
	}
	e.Token, err = InspectToken(windows.GetCurrentProcessToken())
	if err != nil {
		return err
	}
	var inJob int32
	r, _, er := windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob").Call(uintptr(windows.CurrentProcess()), 0, uintptr(unsafe.Pointer(&inJob)))
	if r == 0 {
		return er
	}
	e.InJob = inJob != 0
	// Locate the Rust canonicalize failure without granting ancestor access.
	home, _ := windows.UTF16PtrFromString(filepath.Join(plan.Root, "home"))
	homeHandle, homeErr := windows.CreateFile(home, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	e.Access = append(e.Access, AccessObservation{filepath.Join(plan.Root, "home"), "open directory metadata", fmt.Sprint(homeErr), homeErr == nil})
	if homeErr == nil {
		defer windows.CloseHandle(homeHandle)
		for _, flags := range []uint32{0, 8, 2, 10} {
			var path [32768]uint16
			_, err := windows.GetFinalPathNameByHandle(homeHandle, &path[0], uint32(len(path)), flags)
			e.Access = append(e.Access, AccessObservation{filepath.Join(plan.Root, "home"), fmt.Sprintf("GetFinalPathName flags=%d", flags), fmt.Sprint(err), err == nil})
		}
	}
	for _, path := range []string{filepath.Join(plan.Root, "workspace", "inside.txt"), filepath.Join(plan.Root, "tmp", "inside.txt"), filepath.Join(plan.Root, "runtime", "forbidden.txt"), filepath.Join(plan.Root, "control", "forbidden.txt"), filepath.Join(plan.Outside, "outside.txt"), filepath.Join(plan.Outside, "public-low", "outside.txt"), filepath.Join(plan.Root, "workspace", "..", "..", "outside.txt")} {
		err := os.WriteFile(path, []byte("synthetic isolation canary"), 0600)
		e.Access = append(e.Access, AccessObservation{path, "write", fmt.Sprint(err), err == nil})
	}
	if plan.Profile != "" {
		for _, dir := range []string{plan.Profile, filepath.Dir(plan.Profile)} {
			path := filepath.Join(dir, "outside.txt")
			err := os.WriteFile(path, []byte("synthetic profile write"), 0600)
			e.Access = append(e.Access, AccessObservation{path, "write", fmt.Sprint(err), err == nil})
		}
	}
	for _, path := range []string{filepath.Join(plan.Outside, "sensitive-canary.txt"), filepath.Join(plan.Outside, "sibling-task", "sentinel.txt"), filepath.Join(plan.Root, "control", "sensitive-canary.txt"), filepath.Join(plan.Root, "runtime", filepath.Base(os.Args[0]))} {
		f, err := os.Open(path)
		e.Access = append(e.Access, AccessObservation{path, "read", fmt.Sprint(err), err == nil})
		if err == nil {
			f.Close()
		}
	}
	// Opening for WRITE_DAC must fail even though the host account owns it.
	path := filepath.Join(plan.Root, "workspace", "inside.txt")
	p, _ := windows.UTF16PtrFromString(path)
	h, err := windows.CreateFile(p, windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	e.Access = append(e.Access, AccessObservation{path, "WRITE_DAC", fmt.Sprint(err), err == nil})
	if err == nil {
		windows.CloseHandle(h)
	}
	conn, err := net.DialTimeout("tcp", plan.Loopback, 2*time.Second)
	if err == nil {
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		b := make([]byte, 2)
		_, err = io.ReadFull(conn, b)
		e.LoopbackOK = err == nil && string(b) == "ok"
		conn.Close()
	}
	e.LoopbackError = fmt.Sprint(err)
	if plan.RelayPipe != "" {
		name, _ := windows.UTF16PtrFromString(plan.RelayPipe)
		h, er := windows.CreateNamedPipe(name, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED, windows.PIPE_TYPE_BYTE|windows.PIPE_REJECT_REMOTE_CLIENTS, 255, 8192, 8192, 0, nil)
		e.RelayInstanceDenied = er == windows.ERROR_ACCESS_DENIED
		if er == nil {
			windows.CloseHandle(h)
		}
		h, er = windows.CreateFile(name, windows.WRITE_DAC, 0, nil, windows.OPEN_EXISTING, 0, 0)
		e.RelayACLDenied = er == windows.ERROR_ACCESS_DENIED
		if er == nil {
			windows.CloseHandle(h)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		tr := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return DialRelay(ctx, plan.RelayPipe) }}
		defer tr.CloseIdleConnections()
		client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
		request := func(client *http.Client, endpoint, token string) (int, string, error) {
			req, er := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(`{"model":"fixture-only"}`))
			if er != nil {
				return 0, "", er
			}
			req.Header.Set("Authorization", "Bearer "+token)
			res, er := client.Do(req)
			if er != nil {
				return 0, "", er
			}
			defer res.Body.Close()
			b, er := io.ReadAll(io.LimitReader(res.Body, 1024))
			return res.StatusCode, string(b), er
		}
		status, body, er := request(client, "http://task-broker/v1/responses", plan.RelayToken)
		e.RelayOK = er == nil && status == 200 && body == "fixture-relay-ok"
		e.RelayError = fmt.Sprint(er)
		status, _, er = request(client, "http://task-broker/v1/responses", "wrong-token")
		e.RelayBadTokenRejected = er == nil && status == 401
		status, _, er = request(client, "http://task-broker/arbitrary-host", plan.RelayToken)
		e.RelayRouteRejected = er == nil && status == 403
		endpoint, close, er := StartTaskHTTPRelay(ctx, plan.RelayPipe, plan.RelayToken)
		if er == nil {
			defer close()
			local := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 3 * time.Second}
			defer local.CloseIdleConnections()
			status, body, er = request(local, endpoint+"/responses", plan.RelayToken)
			e.TaskHTTPRelayOK = er == nil && status == 200 && body == "fixture-relay-ok"
		}
		if er != nil {
			e.RelayError += " task HTTP: " + er.Error()
		}
	}
	if len(descendant) == 0 || !descendant[0] {
		path := filepath.Join(plan.Root, "workspace", "descendant-evidence.json")
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		cmd := exec.Command(os.Args[0], "-child", "-plan", planPath, "-descendant")
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS}
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, f, os.Stderr
		err = cmd.Run()
		f.Close()
		if err != nil {
			return fmt.Errorf("descendant: %w", err)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err = json.Unmarshal(b, &e.Descendant); err != nil {
			return err
		}
	}
	if err = json.NewEncoder(os.Stdout).Encode(e); err != nil {
		return err
	}
	return nil
}
