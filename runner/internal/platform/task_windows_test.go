//go:build windows

package platform

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsMissingOrAlteredConfigRefusesWorker(t *testing.T) {
	for _, content := range []string{"", strings.Replace(windowsCodexConfig, "unelevated", "elevated", 1)} {
		root := t.TempDir()
		env, err := Environment(root, nil)
		if err != nil {
			t.Fatal(err)
		}
		if content != "" {
			if err = os.WriteFile(filepath.Join(root, "home", "codex", "config.toml"), []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
		}
		exe, _ := os.Executable()
		p, err := Start(Spec{Executable: exe, Env: env, Directory: filepath.Join(root, "workspace")})
		if p != nil || !errors.Is(err, ErrIsolationUnavailable) {
			t.Fatalf("unsafe worker admitted: %v", err)
		}
	}
}

func TestWindowsDesktopFixture(t *testing.T) {
	if os.Getenv("G9_DESKTOP_FIXTURE") != "1" {
		return
	}
	var inJob int32
	ok, _, err := windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob").Call(uintptr(windows.CurrentProcess()), 0, uintptr(unsafe.Pointer(&inJob)))
	if ok == 0 {
		t.Fatal(err)
	}
	desktop, _, _ := taskUser32.NewProc("GetThreadDesktop").Call(uintptr(windows.GetCurrentThreadId()))
	var name [512]uint16
	var length uint32
	ok, _, err = taskUser32.NewProc("GetUserObjectInformationW").Call(desktop, 2, uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)*2), uintptr(unsafe.Pointer(&length)))
	if ok == 0 {
		t.Fatal(err)
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"inJob": inJob != 0, "desktop": windows.UTF16ToString(name[:])})
	os.Exit(0)
}

func TestWindowsWorkerHasJobAndPrivateDesktop(t *testing.T) {
	root := t.TempDir()
	env, err := Environment(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = PrepareCodexConfig(root); err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	p, err := Start(Spec{Executable: exe, Args: []string{"-test.run=^TestWindowsDesktopFixture$"}, Env: append(env, "G9_DESKTOP_FIXTURE=1"), Directory: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	data, err := io.ReadAll(p.Stdout)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Wait(); err != nil {
		t.Fatal(err)
	}
	var out struct {
		InJob   bool
		Desktop string
	}
	if json.Unmarshal(data, &out) != nil || !out.InJob || !strings.HasPrefix(out.Desktop, "na-task-") {
		t.Fatalf("bad worker: %s", data)
	}
	t.Logf("worker=%s", data)
}
