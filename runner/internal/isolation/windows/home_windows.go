//go:build windows

package isolation

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// Credential-free compatibility experiments. Links are broker-created inside
// the disposable root and point only to that same root's home directory.
func probeHomeEnvironment(env []string, root string, result *ProbeResult) ([]string, error) {
	home := filepath.Join(root, "home")
	value := home
	switch result.HomeMode {
	case "dos", "prewarm", "prewarm-copy":
		for _, entry := range env {
			if strings.HasPrefix(entry, "CODEX_HOME=") {
				result.CodexHome = strings.TrimPrefix(entry, "CODEX_HOME=")
			}
		}
		return env, nil
	case "slash":
		value = strings.ReplaceAll(home, `\`, "/")
	case "extended":
		value = `\\?\` + home
	case "short":
		p, err := windows.UTF16PtrFromString(home)
		if err != nil {
			return nil, err
		}
		var b [32768]uint16
		if _, err = windows.GetShortPathName(p, &b[0], uint32(len(b))); err != nil {
			return nil, err
		}
		value = windows.UTF16ToString(b[:])
	case "profile":
		if result.Profile == "" {
			return nil, fmt.Errorf("profile mode requires AppContainer")
		}
		value = result.Profile // remains sealed read-only
	case "profile-write", "profile-default":
		if result.ProfileHome == "" {
			return nil, fmt.Errorf("profile exception requires AppContainer")
		}
		value = result.ProfileHome
		if result.HomeMode == "profile-default" {
			value = ""
		}
	case "junction", "symlink":
		value = filepath.Join(root, "home-alias")
		if result.HomeMode == "symlink" {
			if err := os.Symlink(home, value); err != nil {
				return nil, err
			}
		} else {
			system, err := windows.GetSystemDirectory()
			if err != nil {
				return nil, err
			}
			if out, err := exec.Command(filepath.Join(system, "cmd.exe"), "/d", "/c", "mklink", "/J", value, home).CombinedOutput(); err != nil {
				return nil, fmt.Errorf("diagnostic junction: %w: %s", err, out)
			}
		}
	case "unset", "empty":
		if err := os.Mkdir(filepath.Join(home, ".codex"), 0700); err != nil {
			return nil, err
		}
		value = ""
	default:
		return nil, fmt.Errorf("unknown diagnostic home mode %q", result.HomeMode)
	}
	result.CodexHome = value
	var out []string
	for _, entry := range env {
		if result.HomeMode == "profile-default" && (strings.HasPrefix(entry, "HOME=") || strings.HasPrefix(entry, "USERPROFILE=")) {
			entry = strings.SplitN(entry, "=", 2)[0] + "=" + result.Profile
		}
		if strings.HasPrefix(entry, "CODEX_HOME=") {
			if result.HomeMode == "unset" || result.HomeMode == "profile-default" {
				continue
			}
			entry = "CODEX_HOME=" + value
		}
		out = append(out, entry)
	}
	return out, nil
}
