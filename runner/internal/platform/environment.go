package platform

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Environment deliberately does not append os.Environ. All user CLI homes,
// login tokens, proxies, plugin paths and shell initialization are excluded.
func Environment(root string, paths []string) ([]string, error) {
	if !filepath.IsAbs(root) {
		return nil, errors.New("absolute task root required")
	}
	for _, d := range []string{root, filepath.Join(root, "home"), filepath.Join(root, "home", "codex"), filepath.Join(root, "tmp"), filepath.Join(root, "workspace"), filepath.Join(root, "config"), filepath.Join(root, "cache"), filepath.Join(root, "data")} {
		if err := PrivateDirectory(d); err != nil {
			return nil, err
		}
	}
	for _, p := range paths {
		if !filepath.IsAbs(p) || strings.ContainsRune(p, os.PathListSeparator) {
			return nil, errors.New("invalid PATH allowlist")
		}
	}
	home := filepath.Join(root, "home")
	tmp := filepath.Join(root, "tmp")
	env := []string{"HOME=" + home, "USERPROFILE=" + home, "TMP=" + tmp, "TEMP=" + tmp, "TMPDIR=" + tmp, "XDG_CONFIG_HOME=" + filepath.Join(root, "config"), "XDG_DATA_HOME=" + filepath.Join(root, "data"), "XDG_CACHE_HOME=" + filepath.Join(root, "cache"), "CODEX_HOME=" + filepath.Join(home, "codex"), "NO_COLOR=1", "TERM=dumb", "LANG=en_US.UTF-8"}
	if runtime.GOOS == "windows" {
		win := os.Getenv("SystemRoot")
		if !filepath.IsAbs(win) {
			return nil, errors.New("SystemRoot missing")
		}
		env = append(env, "SystemRoot="+win, "WINDIR="+win, "APPDATA="+filepath.Join(root, "config"), "LOCALAPPDATA="+filepath.Join(root, "data"))
		paths = append(paths, filepath.Join(win, "System32"), filepath.Join(win, "System32", "WindowsPowerShell", "v1.0"))
	} else {
		paths = append(paths, "/usr/bin", "/bin")
	}
	env = append(env, "PATH="+strings.Join(paths, string(os.PathListSeparator)))
	return env, nil
}
