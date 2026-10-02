package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestWorkerFixture(t *testing.T) {
	if os.Getenv("G9_TEST_WORKER") != "1" {
		return
	}
	if os.Getenv("G9_TEST_WAIT") == "1" {
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	b, _ := json.Marshal(map[string]string{"home": os.Getenv("HOME"), "secret": os.Getenv("G9_FORBIDDEN_SECRET"), "path": os.Getenv("PATH")})
	fmt.Println(string(b))
	os.Exit(0)
}

func TestExplicitEnvironmentAndWorkerCleanup(t *testing.T) {
	t.Setenv("G9_FORBIDDEN_SECRET", "must-not-be-inherited")
	root := t.TempDir()
	env, err := Environment(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	env = append(env, "G9_TEST_WORKER=1")
	p, err := Start(Spec{Executable: exe, Args: []string{"-test.run=^TestWorkerFixture$"}, Env: env, Directory: filepath.Join(root, "workspace")})
	if runtime.GOOS == "windows" {
		if p != nil || !errors.Is(err, ErrIsolationUnavailable) {
			t.Fatalf("Windows worker must fail closed: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(p.Stdout)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Wait(); err != nil {
		t.Fatal(err)
	}
	p.Close()
	if strings.Contains(string(b), "must-not-be-inherited") || !strings.Contains(string(b), `"secret":""`) {
		t.Fatalf("unexpected environment: %s", b)
	}
	p, err = Start(Spec{Executable: exe, Args: []string{"-test.run=^TestWorkerFixture$"}, Env: append(env, "G9_TEST_WAIT=1"), Directory: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = p.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	p.Close()
}
