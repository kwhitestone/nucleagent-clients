// Native bootstrap. Only owner-bound device credentials reach the private bridge.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	release "nucleagent-desktop-runner/catalog"
	"nucleagent-desktop-runner/internal/adapter"
	"nucleagent-desktop-runner/internal/catalog"
	"nucleagent-desktop-runner/internal/platform"
)

func emit(value any) { _ = json.NewEncoder(os.Stdout).Encode(value) }
func main() {
	if err := run(); err != nil {
		emit(map[string]any{"ok": false, "error": err.Error(), "admission": "unavailable"})
		os.Exit(1)
	}
}

func run() error {
	flags := flag.NewFlagSet("nucleagent-runner", flag.ContinueOnError)
	parentStdin := flags.Bool("parent-stdin", false, "cancel installation when the owning shell exits")
	root := flags.String("data-dir", "", "application-private data directory")
	backend := flags.String("backend", "codex", "codex or opencode")
	coreOrigin := flags.String("core-origin", "", "HTTPS Core origin for device binding")
	deviceName := flags.String("name", "My PC", "device display name")
	enabled := flags.Bool("enable", false, "enable private task admission")
	consent := flags.Bool("consent-native-access", false, "acknowledge that trusted tasks run with this user's file and network access")
	if len(os.Args) < 2 {
		return errors.New("usage: nucleagent-runner doctor|status|install|verify|bind|device-status|renew|revoke|run [--data-dir PATH] [--backend codex|opencode]")
	}
	command := os.Args[1]
	if err := flags.Parse(os.Args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if command == "doctor" {
		identity, err := platform.InspectIdentity()
		if err != nil {
			return err
		}
		allowed := platform.RequireNativeUser()
		reason := ""
		if allowed != nil {
			reason = allowed.Error()
		}
		emit(map[string]any{"identity": identity, "nativeUserReady": allowed == nil, "reason": reason, "admission": "unavailable", "version": "0.2.0", "distribution": "engineering-preview", "noSandbox": runtime.GOOS != "windows", "windowsSandbox": "unelevated (per-task config.toml)"})
		return nil
	}
	if command != "status" && command != "install" && command != "verify" && command != "bind" && command != "renew" && command != "revoke" && command != "run" && command != "device-status" {
		return errors.New("unsupported command")
	}
	if *backend != "codex" && *backend != "opencode" {
		return errors.New("unsupported backend")
	}
	if err := platform.RequireNativeUser(); err != nil {
		return err
	}
	if *root == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return err
		}
		if runtime.GOOS == "windows" {
			base = os.Getenv("LOCALAPPDATA")
		}
		*root = filepath.Join(base, "NucleAgent", "runner")
	}
	if !filepath.IsAbs(*root) {
		return errors.New("absolute application data directory required")
	}
	if err := platform.PrivateDirectory(*root); err != nil {
		return err
	}
	lock, err := platform.Lock(filepath.Join(*root, "runner.lock"))
	if err != nil {
		return errors.New("runner data directory is already owned or unsafe")
	}
	defer lock.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if *parentStdin {
		go func() { _, _ = io.Copy(io.Discard, os.Stdin); cancel() }()
	}
	if command == "bind" || command == "renew" || command == "revoke" || command == "device-status" {
		return deviceCommand(ctx, command, *root, *coreOrigin, *deviceName)
	}
	if command == "run" && (*backend != "codex" || !*enabled || !*consent) {
		return errors.New("run requires codex, --enable and --consent-native-access")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(release.PublicKey))
	if err != nil {
		return errors.New("invalid embedded release key")
	}
	var minimum uint64 = 1
	sequencePath := filepath.Join(*root, "catalog-sequence.json")
	if data, readErr := os.ReadFile(sequencePath); readErr == nil {
		if json.Unmarshal(data, &minimum) != nil || minimum == 0 {
			return errors.New("catalog sequence ledger invalid")
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	manifest, err := catalog.Decode(release.Catalog, ed25519.PublicKey(key), minimum)
	if err != nil {
		return err
	}
	if manifest.Sequence > minimum || minimum == 1 {
		if err = writeJSON(sequencePath, manifest.Sequence); err != nil {
			return err
		}
	}
	bundle, err := manifest.Select(*backend, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	store := catalog.NewStore(filepath.Join(*root, "tools"))
	generation := store.Generation(bundle)
	if command == "status" {
		state := "missing"
		if _, err = os.Lstat(generation); err == nil {
			state = "installed-unprobed"
			if err = catalog.Verify(generation, bundle); err != nil {
				state = "incompatible"
			}
		}
		emit(map[string]any{"backend": *backend, "generation": bundle.ID, "state": state, "admission": "unavailable", "reason": "start run with explicit native-access consent to register", "sequence": manifest.Sequence})
		return nil
	}
	if command == "verify" {
		if err = catalog.Verify(generation, bundle); err != nil {
			return err
		}
		emit(map[string]any{"integrity": "verified", "generation": bundle.ID, "admission": "unavailable"})
		return nil
	}
	installCtx, timeout := context.WithTimeout(ctx, 20*time.Minute)
	defer timeout()
	// The global application lock also serializes install/probe/sequence updates
	// across processes. A download alone never means an executor is ready.
	generation, err = store.Install(installCtx, bundle, func(p catalog.Progress) { emit(p) }, func(ctx context.Context, dir string, b catalog.Bundle) error {
		if err := adapter.Version(ctx, dir, b); err != nil {
			return err
		}
		return adapter.Probe(ctx, dir, b)
	})
	if err != nil {
		return err
	}
	if command == "run" {
		return runBridge(ctx, *root, generation, bundle)
	}
	emit(map[string]any{"generation": bundle.ID, "state": "probed", "path": generation, "admission": "unavailable", "reason": "start run with explicit native-access consent to register"})
	return nil
}

func writeJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "ledger-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return fmt.Errorf("save sequence: %w", err)
	}
	return nil
}
