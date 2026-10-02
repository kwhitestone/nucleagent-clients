package vault

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"nucleagent-desktop-runner/internal/platform"
)

func TestNativeCredentialRoundTrip(t *testing.T) {
	if err := platform.RequireNativeUser(); err != nil {
		t.Skip("native non-elevated user required: " + err.Error())
	}
	root := t.TempDir()
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	expected := Credential{DeviceID: "fixture-device", InstanceID: "fixture-instance", Token: "fixture-device-secret", PrivateKey: "fixture-private-key", CoreOrigin: "https://fixture.invalid"}
	defer store.Delete()
	if err = store.Save(expected); err != nil {
		t.Fatal(err)
	}
	actual, err := store.Load()
	if err != nil || actual != expected {
		t.Fatalf("OS credential round trip failed: %v", err)
	}
	if runtime.GOOS == "windows" {
		data, err := os.ReadFile(filepath.Join(root, "device.dpapi"))
		if err != nil {
			t.Fatal(err)
		}
		if len(data) == 0 {
			t.Fatal("empty encrypted record")
		}
	}
	if err = store.Delete(); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Load(); err == nil {
		t.Fatal("deleted credential was returned")
	}
}
