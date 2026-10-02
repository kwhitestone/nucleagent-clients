//go:build windows

package isolation

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var user32 = windows.NewLazySystemDLL("user32.dll")

// SetProbeACL operates exclusively on the disposable, broker-owned probe tree.
// It must never be used to grant access recursively to a host/system directory.
func SetProbeACL(path, sid string, writable bool) error {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	rights := "0x1200a9"
	label := "ME" // file read/execute; no write, delete, ownership, or ACL rights
	if writable {
		rights = "0x1301bf"
		label = "LW"
	} // modify, not WRITE_DAC/WRITE_OWNER
	allow := ""
	if sid != "" {
		allow = "(A;OICI;" + rights + ";;;" + sid + ")"
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + u.User.Sid.String() + ")" + allow + "(A;OICI;RC;;;OW)S:(ML;OICI;NW;;;" + label + ")")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	sacl, _, err := sd.SACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION|windows.LABEL_SECURITY_INFORMATION, nil, nil, dacl, sacl)
}

func checkPath(path string) error {
	if !filepath.IsAbs(path) || strings.HasPrefix(path, `\\`) {
		return fmt.Errorf("local absolute path required")
	}
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		u, err := windows.UTF16PtrFromString(p)
		if err != nil {
			return err
		}
		a, err := windows.GetFileAttributes(u)
		if err != nil {
			return err
		}
		if a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("reparse point rejected: %s", p)
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}

type desktop struct {
	station, desk windows.Handle
	name          string
}

func (d *desktop) close() error {
	var failures []error
	if d.desk != 0 {
		if r, _, err := user32.NewProc("CloseDesktop").Call(uintptr(d.desk)); r == 0 {
			failures = append(failures, err)
		}
	}
	if d.station != 0 {
		if r, _, err := user32.NewProc("CloseWindowStation").Call(uintptr(d.station)); r == 0 {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func userObjectName(h uintptr) (string, error) {
	if h == 0 {
		return "", fmt.Errorf("null user object")
	}
	var b [512]uint16
	var length uint32
	r, _, err := user32.NewProc("GetUserObjectInformationW").Call(h, 2, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)*2), uintptr(unsafe.Pointer(&length)))
	if r == 0 {
		return "", err
	}
	return windows.UTF16ToString(b[:]), nil
}

// The probe is single-threaded at application level. The temporary process-wide
// window-station switch must be redesigned before reuse by a concurrent broker.
func privateDesktop(sid string) (*desktop, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;" + u.User.Sid.String() + ")(A;;GA;;;" + sid + ")S:(ML;;NW;;;LW)")
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name := "NucleAgentProbe-" + strings.TrimPrefix(sid, "S-1-5-21-")
	n, _ := windows.UTF16PtrFromString(name)
	h, _, er := user32.NewProc("CreateWindowStationW").Call(uintptr(unsafe.Pointer(n)), 0, 0xf037f, uintptr(unsafe.Pointer(&sa)))
	if h == 0 {
		return nil, fmt.Errorf("CreateWindowStationW: %w", er)
	}
	d := &desktop{station: windows.Handle(h), name: name + `\worker`}
	previous, _, er := user32.NewProc("GetProcessWindowStation").Call()
	if previous == 0 {
		d.close()
		return nil, er
	}
	r, _, er := user32.NewProc("SetProcessWindowStation").Call(h)
	if r == 0 {
		d.close()
		return nil, er
	}
	dn, _ := windows.UTF16PtrFromString("worker")
	dh, _, createErr := user32.NewProc("CreateDesktopW").Call(uintptr(unsafe.Pointer(dn)), 0, 0, 0, 0xf01ff, uintptr(unsafe.Pointer(&sa)))
	d.desk = windows.Handle(dh)
	r, _, restoreErr := user32.NewProc("SetProcessWindowStation").Call(previous)
	runtime.KeepAlive(sd)
	if r == 0 {
		d.close()
		return nil, fmt.Errorf("restore window station: %w", restoreErr)
	}
	if dh == 0 {
		d.close()
		return nil, fmt.Errorf("CreateDesktopW: %w", createErr)
	}
	return d, nil
}

func copyProbeFile(from, to string) error {
	if err := checkPath(from); err != nil {
		return err
	}
	b, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	return os.WriteFile(to, b, 0600)
}
