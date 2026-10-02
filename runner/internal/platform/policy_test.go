package platform

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSingleOwnerLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	first, err := Lock(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Lock(path)
	if err == nil {
		second.Close()
		t.Fatal("second owner admitted")
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := Lock(path)
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
}

func TestPrivateDirectoryRejectsLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("non-elevated symlink privilege is not required")
	}
	base := t.TempDir()
	target := filepath.Join(base, "target")
	link := filepath.Join(base, "link")
	if err := os.Mkdir(target, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := PrivateDirectory(link); err == nil {
		t.Fatal("private directory followed symlink")
	}
}

func TestLinuxCannotMasqueradeAsNativeDelivery(t *testing.T) {
	id, err := InspectIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "linux" && (id.Supported || RequireNativeUser() == nil) {
		t.Fatal("Linux admitted as PC delivery")
	}
	if id.Elevated && RequireNativeUser() == nil {
		t.Fatal("elevated process admitted")
	}
}
