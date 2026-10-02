//go:build windows

// Package isolation implements experimental Windows isolation probes. It is not
// an admission policy: callers must not use probe success to enable production.
package isolation

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var advapi = windows.NewLazySystemDLL("advapi32.dll")

type Group struct {
	SID        string
	Attributes uint32
}
type TokenEvidence struct {
	Restricted                                               []Group
	Capabilities                                             []Group
	Groups                                                   []Group
	Privileges                                               []windows.LUIDAndAttributes
	Integrity                                                string
	Package                                                  string
	LessPrivilegedAppContainer                               uint32
	LPACQueryError                                           string
	NoAllAppPackages                                         uint64
	MandatoryPolicy, Elevated, HasRestrictions, AppContainer uint32
}

func tokenInfo(t windows.Token, class uint32) ([]byte, error) {
	var n uint32
	err := windows.GetTokenInformation(t, class, nil, 0, &n)
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, fmt.Errorf("token class %d size: %w", class, err)
	}
	b := make([]byte, n)
	err = windows.GetTokenInformation(t, class, &b[0], n, &n)
	return b, err
}

func InspectToken(t windows.Token) (e TokenEvidence, err error) {
	for _, item := range []struct {
		class uint32
		dst   *[]Group
	}{{windows.TokenRestrictedSids, &e.Restricted}, {windows.TokenGroups, &e.Groups}, {30, &e.Capabilities}} { // TokenCapabilities
		b, er := tokenInfo(t, item.class)
		if er != nil {
			return e, er
		}
		for _, g := range (*windows.Tokengroups)(unsafe.Pointer(&b[0])).AllGroups() {
			*item.dst = append(*item.dst, Group{g.Sid.String(), g.Attributes})
		}
		runtime.KeepAlive(b)
	}
	b, err := tokenInfo(t, windows.TokenPrivileges)
	if err != nil {
		return e, err
	}
	e.Privileges = append(e.Privileges, (*windows.Tokenprivileges)(unsafe.Pointer(&b[0])).AllPrivileges()...)
	b, err = tokenInfo(t, windows.TokenIntegrityLevel)
	if err != nil {
		return e, err
	}
	e.Integrity = (*windows.Tokenmandatorylabel)(unsafe.Pointer(&b[0])).Label.Sid.String()
	runtime.KeepAlive(b)
	for _, item := range []struct {
		class uint32
		dst   *uint32
	}{{windows.TokenMandatoryPolicy, &e.MandatoryPolicy}, {windows.TokenElevation, &e.Elevated}, {windows.TokenHasRestrictions, &e.HasRestrictions}, {29, &e.AppContainer}} { // TokenIsAppContainer
		var length uint32
		if err = windows.GetTokenInformation(t, item.class, (*byte)(unsafe.Pointer(item.dst)), 4, &length); err != nil {
			return e, err
		}
	}
	if e.AppContainer != 0 {
		b, err = tokenInfo(t, 31)
		if err != nil {
			return e, err
		}
		s := *(**windows.SID)(unsafe.Pointer(&b[0]))
		if s != nil {
			e.Package = s.String()
		}
		runtime.KeepAlive(b)
	}
	return e, nil
}

func newSID() (*windows.SID, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	return windows.StringToSid(fmt.Sprintf("S-1-5-21-%d-%d-%d-%d", binary.LittleEndian.Uint32(b[:4]), binary.LittleEndian.Uint32(b[4:8]), binary.LittleEndian.Uint32(b[8:12]), binary.LittleEndian.Uint32(b[12:])))
}

// Full read/write restrictions. Never WRITE_RESTRICTED or SANDBOX_INERT.
func restrictedToken(sid *windows.SID, safer bool) (windows.Token, error) {
	var source windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_ADJUST_DEFAULT, &source); err != nil {
		return 0, fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer source.Close()
	if safer {
		var level windows.Handle
		r, _, er := advapi.NewProc("SaferCreateLevel").Call(1, 0x10000, 1, uintptr(unsafe.Pointer(&level)), 0)
		if r == 0 {
			return 0, fmt.Errorf("SaferCreateLevel: %w", er)
		}
		defer advapi.NewProc("SaferCloseLevel").Call(uintptr(level))
		var computed windows.Token
		r, _, er = advapi.NewProc("SaferComputeTokenFromLevel").Call(uintptr(level), uintptr(source), uintptr(unsafe.Pointer(&computed)), 0, 0)
		if r == 0 {
			return 0, fmt.Errorf("SaferComputeTokenFromLevel: %w", er)
		}
		defer computed.Close()
		source = computed
	}
	groups, err := source.GetTokenGroups()
	if err != nil {
		return 0, err
	}
	var disabled []windows.SIDAndAttributes
	for _, g := range groups.AllGroups() {
		// Disable privileged aliases and owner groups. System runtime access
		// still needs ordinary groups on the normal side of the dual check.
		if privilegedGroup(g) && g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			disabled = append(disabled, g)
		}
	}
	var ptr *windows.SIDAndAttributes
	if len(disabled) > 0 {
		ptr = &disabled[0]
	}
	restrict := windows.SIDAndAttributes{Sid: sid}
	var restrictCount uintptr
	var restrictPtr *windows.SIDAndAttributes
	if sid != nil {
		restrictCount = 1
		restrictPtr = &restrict
	}
	var token windows.Token
	r, _, er := advapi.NewProc("CreateRestrictedToken").Call(uintptr(source), 1, uintptr(len(disabled)), uintptr(unsafe.Pointer(ptr)), 0, 0, restrictCount, uintptr(unsafe.Pointer(restrictPtr)), uintptr(unsafe.Pointer(&token)))
	runtime.KeepAlive(groups)
	runtime.KeepAlive(disabled)
	runtime.KeepAlive(sid)
	if r == 0 {
		return 0, fmt.Errorf("CreateRestrictedToken: %w", er)
	}
	low, err := windows.StringToSid("S-1-16-4096")
	if err != nil {
		token.Close()
		return 0, err
	}
	ml := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: low, Attributes: windows.SE_GROUP_INTEGRITY}}
	if err = windows.SetTokenInformation(token, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&ml)), ml.Size()); err != nil {
		token.Close()
		return 0, err
	}
	// Preserve and verify inherited NO_WRITE_UP. Setting MandatoryPolicy needs
	// SeTcbPrivilege; do not request that privilege from an ordinary-user broker.
	return token, nil
}

func verifyToken(e TokenEvidence, sid string) error {
	validSID := len(e.Restricted) == 1 && e.Restricted[0].SID == sid && e.AppContainer == 0 && len(e.Capabilities) == 0
	if sid == "" {
		validSID = len(e.Restricted) == 0 && e.AppContainer == 0
	}
	if strings.HasPrefix(sid, "S-1-15-2-") {
		validSID = e.AppContainer == 1 && e.Package == sid && len(e.Restricted) == 0
		if len(e.Capabilities) > 1 {
			validSID = false
		}
		for _, cap := range e.Capabilities {
			if cap.SID != "S-1-15-3-1" || cap.Attributes != windows.SE_GROUP_ENABLED {
				validSID = false
			}
		}
	}
	if !validSID || e.Integrity != "S-1-16-4096" || e.Elevated != 0 || e.MandatoryPolicy&1 == 0 || e.HasRestrictions == 0 {
		return fmt.Errorf("isolation token mismatch: %+v", e)
	}
	for _, p := range e.Privileges {
		if p.Luid.HighPart != 0 || p.Luid.LowPart != 23 {
			return fmt.Errorf("unexpected retained privilege: %+v", p)
		}
	} // SeChangeNotifyPrivilege
	for _, g := range e.Groups {
		if g.Attributes&windows.SE_GROUP_ENABLED != 0 && privilegedGroup(windows.SIDAndAttributes{Sid: mustSID(g.SID), Attributes: g.Attributes}) {
			return fmt.Errorf("unexpected enabled group: %s", g.SID)
		}
	}
	return nil
}

func mustSID(s string) *windows.SID {
	sid, err := windows.StringToSid(s)
	if err != nil {
		panic(err)
	}
	return sid
}
func privilegedGroup(g windows.SIDAndAttributes) bool {
	if g.Attributes&windows.SE_GROUP_OWNER != 0 {
		return true
	}
	switch g.Sid.String() {
	case "S-1-5-32-544", "S-1-5-32-547", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551":
		return true
	}
	return false
}
