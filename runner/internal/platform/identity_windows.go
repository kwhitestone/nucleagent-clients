//go:build windows

package platform

import (
	"errors"
	"golang.org/x/sys/windows"
	"unsafe"
)

func elevatedIdentity() (bool, error) {
	token := windows.GetCurrentProcessToken()
	var elevated, length uint32
	if err := windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&elevated)), 4, &length); err != nil {
		return true, err
	}
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return true, err
	}
	// Group inspection also catches UAC-disabled administrator sessions.
	groups, err := token.GetTokenGroups()
	if err != nil {
		return true, err
	}
	for _, group := range groups.AllGroups() {
		if group.Sid.Equals(sid) && group.Attributes&windows.SE_GROUP_ENABLED != 0 {
			return true, nil
		}
	}
	return elevated != 0, nil
}

func minimumOS() error {
	v := windows.RtlGetVersion()
	if v.MajorVersion < 10 || v.BuildNumber < 26100 {
		return errors.New("Windows 11 24H2 or later required")
	}
	return nil
}
