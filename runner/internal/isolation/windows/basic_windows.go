//go:build windows

package isolation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// A Low IL canary with an actual write deny distinguishes DACL enforcement
// from mandatory integrity enforcement. Only the disposable probe tree changes.
func prepareBasicDeniedCanary(path string) error {
	if err := os.Mkdir(path, 0700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(path, "outside.txt"), []byte("broker sentinel"), 0600); err != nil {
		return err
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	s := u.User.Sid.String()
	sd, err := windows.SecurityDescriptorFromString("D:P(D;OICI;GW;;;" + s + ")(A;OICI;FA;;;" + s + ")S:(ML;OICI;NW;;;LW)")
	if err != nil {
		return err
	}
	d, _, err := sd.DACL()
	if err != nil {
		return err
	}
	l, _, err := sd.SACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION|windows.LABEL_SECURITY_INFORMATION, nil, nil, d, l)
}

// No window text, messages, input, or clipboard data is accessed. The disposable
// child tries to open/enumerate the host desktop and immediately restores its
// station. Do not use this process-wide station switch in a concurrent broker.
func hostDesktopProbe() []AccessObservation {
	var observations []AccessObservation
	name, _ := windows.UTF16PtrFromString("WinSta0")
	h, _, er := user32.NewProc("OpenWindowStationW").Call(uintptr(unsafe.Pointer(name)), 0, 3)
	observations = append(observations, AccessObservation{"WinSta0", "open ENUMDESKTOPS|READATTRIBUTES", fmt.Sprint(er), h != 0})
	if h == 0 {
		return observations
	}
	defer user32.NewProc("CloseWindowStation").Call(h)
	old, _, _ := user32.NewProc("GetProcessWindowStation").Call()
	r, _, er := user32.NewProc("SetProcessWindowStation").Call(h)
	observations = append(observations, AccessObservation{"WinSta0", "SetProcessWindowStation", fmt.Sprint(er), r != 0})
	if r == 0 {
		return observations
	}
	defer func() {
		if r, _, _ := user32.NewProc("SetProcessWindowStation").Call(old); r == 0 {
			panic("cannot restore child station")
		}
	}()
	name, _ = windows.UTF16PtrFromString("Default")
	desk, _, er := user32.NewProc("OpenDesktopW").Call(uintptr(unsafe.Pointer(name)), 0, 0, 0x41)
	observations = append(observations, AccessObservation{`WinSta0\Default`, "open READOBJECTS|ENUMERATE", fmt.Sprint(er), desk != 0})
	if desk == 0 {
		return observations
	}
	defer user32.NewProc("CloseDesktop").Call(desk)
	count := 0
	callback := syscall.NewCallback(func(_ uintptr, _ uintptr) uintptr { count++; return 1 })
	r, _, er = user32.NewProc("EnumDesktopWindows").Call(desk, callback, 0)
	observations = append(observations, AccessObservation{`WinSta0\Default`, fmt.Sprintf("EnumDesktopWindows count=%d", count), fmt.Sprint(er), r != 0})
	return observations
}

func verifyBasicBoundary(r *ProbeResult) error {
	var e childEvidence
	if err := json.Unmarshal([]byte(r.Stdout), &e); err != nil {
		return err
	}
	if e.Descendant == nil {
		return fmt.Errorf("basic descendant evidence missing")
	}
	var failures []string
	for i, child := range []*childEvidence{&e, e.Descendant} {
		if err := verifyBasicToken(child.Token); err != nil {
			return err
		}
		if !child.InJob || child.DesktopError != "" || child.WindowStation+`\`+child.Desktop != r.Desktop {
			return fmt.Errorf("basic child %d Job/desktop mismatch", i)
		}
		inside := false
		outside := false
		for _, o := range child.Access {
			if o.Operation == "write" && o.Object == filepath.Join(r.Root, "workspace", "inside.txt") {
				inside = o.Allowed
			}
			if o.Operation == "write" && strings.HasSuffix(o.Object, `\public-low\outside.txt`) {
				outside = true
				if o.Allowed {
					failures = append(failures, fmt.Sprintf("child %d wrote outside task root: %s", i, o.Object))
				}
			}
			if o.Object == `WinSta0\Default` && o.Allowed {
				failures = append(failures, fmt.Sprintf("child %d accessed host desktop: %s", i, o.Operation))
			}
		}
		if !inside || !outside {
			return fmt.Errorf("basic child %d missing positive workspace/outside probe", i)
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("B' boundary failed: %s", strings.Join(failures, "; "))
	}
	return nil
}

// B' is an explicit feasibility candidate, not a fallback for AppContainer.
// restrictedToken(nil, false) uses DISABLE_MAX_PRIVILEGE and zero restricting
// SIDs. Same-user ACL grants remain effective: this is NOT a file write sandbox.
func verifyBasicToken(e TokenEvidence) error {
	if err := verifyToken(e, ""); err != nil {
		return err
	}
	if e.Package != "" || len(e.Capabilities) != 0 {
		return fmt.Errorf("basic token unexpectedly has package/capabilities")
	}
	for _, g := range e.Groups {
		if privilegedGroup(windows.SIDAndAttributes{Sid: mustSID(g.SID), Attributes: g.Attributes}) && g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			return fmt.Errorf("privileged group is not deny-only: %s", g.SID)
		}
	}
	return nil
}
