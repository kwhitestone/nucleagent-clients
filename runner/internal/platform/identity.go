package platform

import (
	"errors"
	"runtime"
)

type Identity struct {
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	Elevated  bool   `json:"elevated"`
	Supported bool   `json:"supported"`
}

func InspectIdentity() (Identity, error) {
	elevated, err := elevatedIdentity()
	return Identity{OS: runtime.GOOS, Arch: runtime.GOARCH, Elevated: elevated, Supported: runtime.GOOS == "windows" && runtime.GOARCH == "amd64" || runtime.GOOS == "darwin" && runtime.GOARCH == "arm64"}, err
}

// RequireNativeUser is deliberately not bypassable with a CLI flag. Linux
// fixture tests call libraries directly; Linux is never a delivery platform.
func RequireNativeUser() error {
	identity, err := InspectIdentity()
	if err != nil {
		return err
	}
	if identity.Elevated {
		return errors.New("runner requires a non-elevated user; restart from a standard user session")
	}
	if !identity.Supported {
		return errors.New("supported platforms: Windows 11 x64 and macOS 15 Apple Silicon")
	}
	return minimumOS()
}
