//go:build windows

package platform

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var taskUser32 = windows.NewLazySystemDLL("user32.dll")

func taskIsolationAvailable() error {
	for _, name := range []string{"CreateDesktopW", "CloseDesktop", "GetProcessWindowStation", "GetUserObjectInformationW"} {
		if err := taskUser32.NewProc(name).Find(); err != nil {
			return errors.Join(ErrIsolationUnavailable, err)
		}
	}
	return nil
}

func rejectReparsePath(path string) error {
	if !filepath.IsAbs(path) || strings.HasPrefix(path, `\\`) {
		return errors.New("local absolute task path required")
	}
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		u, err := windows.UTF16PtrFromString(p)
		if err != nil {
			return err
		}
		attrs, err := windows.GetFileAttributes(u)
		if err != nil {
			return err
		}
		if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("task reparse point rejected")
		}
		if filepath.Dir(p) == p {
			return nil
		}
	}
}

func validateWindowsTask(s Spec) error {
	env := map[string]string{}
	for _, v := range s.Env {
		k, value, ok := strings.Cut(v, "=")
		k = strings.ToUpper(k)
		if !ok || k == "" {
			return errors.New("invalid task environment")
		}
		if _, ok := env[k]; ok {
			return errors.New("duplicate environment key")
		}
		env[k] = value
	}
	root := filepath.Dir(s.Directory)
	if filepath.Base(s.Directory) != "workspace" || env["CODEX_HOME"] != filepath.Join(root, "home", "codex") || env["TEMP"] != filepath.Join(root, "tmp") || env["TMP"] != env["TEMP"] {
		return errors.New("task paths do not match broker layout")
	}
	path := filepath.Join(env["CODEX_HOME"], "config.toml")
	for _, p := range []string{root, s.Directory, env["CODEX_HOME"], env["TEMP"], path} {
		if err := rejectReparsePath(p); err != nil {
			return err
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if string(b) != windowsCodexConfig {
		return errors.New("missing or altered per-task Windows sandbox config")
	}
	// Reapply private DACLs and read them back before process creation. This is
	// same-user task privacy; Codex's restricted-token child enforces write scope.
	for _, p := range []string{root, filepath.Join(root, "home"), env["CODEX_HOME"], s.Directory, env["TEMP"]} {
		if err := PrivateDirectory(p); err != nil {
			return err
		}
		if err := verifyTaskACL(p); err != nil {
			return err
		}
	}
	return nil
}

func verifyTaskACL(path string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 || acl == nil || acl.AceCount != 1 {
		return errors.New("private directory DACL not protected or not exclusive")
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err = windows.GetAce(acl, 0, &ace); err != nil {
		return err
	}
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE || ace.Mask != 0x1f01ff || !sid.Equals(user.User.Sid) {
		return errors.New("private directory ACL verification failed")
	}

	return nil
}

type taskDesktop struct {
	handle windows.Handle
	name   string
}

// A random desktop in the existing station avoids a process-wide station
// switch in the concurrent broker. No diagnostic probe code participates.
func newTaskDesktop() (*taskDesktop, error) {
	if err := taskIsolationAvailable(); err != nil {
		return nil, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return nil, err
	}
	name := "na-task-" + hex.EncodeToString(random[:])
	n, _ := windows.UTF16PtrFromString(name)
	station, _, err := taskUser32.NewProc("GetProcessWindowStation").Call()
	if station == 0 {
		return nil, err
	}
	var stationName [512]uint16
	var length uint32
	ok, _, err := taskUser32.NewProc("GetUserObjectInformationW").Call(station, 2, uintptr(unsafe.Pointer(&stationName[0])), uintptr(len(stationName)*2), uintptr(unsafe.Pointer(&length)))
	if ok == 0 {
		return nil, err
	}
	h, _, err := taskUser32.NewProc("CreateDesktopW").Call(uintptr(unsafe.Pointer(n)), 0, 0, 0, 0x1ff, uintptr(unsafe.Pointer(&sa)))
	if h == 0 {
		return nil, fmt.Errorf("create private desktop: %w", err)
	}
	return &taskDesktop{windows.Handle(h), windows.UTF16ToString(stationName[:]) + `\` + name}, nil
}

func (d *taskDesktop) close() error {
	ok, _, err := taskUser32.NewProc("CloseDesktop").Call(uintptr(d.handle))
	if ok == 0 {
		return err
	}
	return nil
}

// JOBOBJECT_BASIC_ACCOUNTING_INFORMATION (WinNT.h).
type jobAccounting struct {
	TotalUserTime, TotalKernelTime, ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime int64
	TotalPageFaultCount, TotalProcesses, ActiveProcesses, TotalTerminatedProcesses     uint32
}
