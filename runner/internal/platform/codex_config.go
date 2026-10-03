package platform

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

const windowsCodexConfig = "approval_policy = \"never\"\nsandbox_mode = \"workspace-write\"\n[windows]\nsandbox = \"unelevated\"\n"

// PrepareCodexConfig writes only into a fresh broker-owned task home. Existing
// content is never silently accepted or overwritten, including a linked file.
func PrepareCodexConfig(root string) error {
	config := "approval_policy = \"never\"\nsandbox_mode = \"workspace-write\"\n"
	if runtime.GOOS == "windows" {
		config = windowsCodexConfig
	}
	path := filepath.Join(root, "home", "codex", "config.toml")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(config)
	return errors.Join(err, f.Sync(), f.Close())
}
