//go:build windows

package isolation

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

type AccessObservation struct {
	Object, Operation, Error string
	Allowed                  bool
}

// Access probes impersonate on a locked thread, before launching any child.
// They locate closure failures; they are not evidence of child/E2E execution.
func accessProbe(token windows.Token, root string) ([]AccessObservation, error) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	sentinel := filepath.Join(root, "control", "sensitive-canary.txt")
	if err = os.WriteFile(sentinel, []byte("synthetic-canary-not-a-credential"), 0600); err != nil {
		return nil, err
	}
	var imp windows.Token
	if err = windows.DuplicateTokenEx(token, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &imp); err != nil {
		return nil, err
	}
	defer imp.Close()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err = windows.SetThreadToken(nil, imp); err != nil {
		return nil, err
	}
	defer func() {
		if err := windows.RevertToSelf(); err != nil {
			panic("cannot revert probe impersonation")
		}
	}()
	var observations []AccessObservation
	for _, item := range []struct {
		path        string
		access      uint32
		disposition uint32
	}{{filepath.Join(system, "ntdll.dll"), windows.GENERIC_READ, windows.OPEN_EXISTING}, {filepath.Join(system, "kernel32.dll"), windows.GENERIC_READ, windows.OPEN_EXISTING}, {sentinel, windows.GENERIC_READ, windows.OPEN_EXISTING}, {filepath.Join(root, "workspace", "access-probe.txt"), windows.GENERIC_WRITE, windows.CREATE_NEW}, {filepath.Join(root, "control", "outside.txt"), windows.GENERIC_WRITE, windows.CREATE_NEW}} {
		p, _ := windows.UTF16PtrFromString(item.path)
		h, er := windows.CreateFile(p, item.access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, item.disposition, windows.FILE_ATTRIBUTE_NORMAL, 0)
		op := "read"
		if item.access == windows.GENERIC_WRITE {
			op = "write"
		}
		observations = append(observations, AccessObservation{item.path, op, fmt.Sprint(er), er == nil})
		if er == nil {
			windows.CloseHandle(h)
		}
	}
	for _, path := range []string{`\KnownDlls\ntdll.dll`, `\KnownDlls\kernel32.dll`, `\KnownDlls\kernelbase.dll`} {
		n, _ := windows.NewNTUnicodeString(path)
		oa := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), ObjectName: n, Attributes: windows.OBJ_CASE_INSENSITIVE}
		var h windows.Handle
		status, _, _ := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtOpenSection").Call(uintptr(unsafe.Pointer(&h)), 0xc, uintptr(unsafe.Pointer(&oa)))
		observations = append(observations, AccessObservation{path, "SECTION_MAP_READ|SECTION_MAP_EXECUTE", fmt.Sprintf("NTSTATUS 0x%08x", uint32(status)), status == 0})
		if status == 0 {
			windows.CloseHandle(h)
		}
	}
	key, _ := windows.UTF16PtrFromString(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`)
	var h windows.Handle
	err = windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE, key, 0, windows.KEY_READ, &h)
	observations = append(observations, AccessObservation{`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "KEY_READ", fmt.Sprint(err), err == nil})
	if err == nil {
		windows.RegCloseKey(h)
	}
	return observations, nil
}
