//go:build windows

package isolation

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// These options apply only to disposable probes, never production admission.
type CompatibilityOptions struct {
	Capabilities []string
	LPAC         bool
}

func compatibilityCapabilities(names []string) ([]windows.SIDAndAttributes, error) {
	allowed := map[string]bool{"codeGeneration": true, "registryRead": true, "lpacCom": true, "lpacIdentityServices": true, "lpacAppExperience": true, "lpacFileAccess": true}
	var result []windows.SIDAndAttributes
	seen := map[string]bool{}
	for _, name := range names {
		if !allowed[name] || seen[name] {
			return nil, fmt.Errorf("unsupported or duplicate diagnostic capability %q", name)
		}
		seen[name] = true
		p, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return nil, err
		}
		var groups, caps **windows.SID
		var ng, nc uint32
		r, _, er := windows.NewLazySystemDLL("kernelbase.dll").NewProc("DeriveCapabilitySidsFromName").Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&groups)), uintptr(unsafe.Pointer(&ng)), uintptr(unsafe.Pointer(&caps)), uintptr(unsafe.Pointer(&nc)))
		if r == 0 {
			return nil, fmt.Errorf("DeriveCapabilitySidsFromName: %w", er)
		}
		var sid *windows.SID
		for _, s := range unsafe.Slice(caps, nc) {
			if nc == 1 {
				sid, err = windows.StringToSid(s.String())
			}
			windows.LocalFree(windows.Handle(unsafe.Pointer(s)))
		}
		for _, s := range unsafe.Slice(groups, ng) {
			windows.LocalFree(windows.Handle(unsafe.Pointer(s)))
		}
		windows.LocalFree(windows.Handle(unsafe.Pointer(caps)))
		windows.LocalFree(windows.Handle(unsafe.Pointer(groups)))
		if err != nil {
			return nil, err
		}
		if sid == nil {
			return nil, fmt.Errorf("expected one capability SID for %s", name)
		}
		result = append(result, windows.SIDAndAttributes{Sid: sid, Attributes: windows.SE_GROUP_ENABLED})
	}
	return result, nil
}

func verifyCompatibilityToken(e TokenEvidence, r *ProbeResult) error {
	if len(r.CapabilitySIDs) == 0 && !r.LPAC {
		return verifyToken(e, r.SID)
	}
	if len(e.Capabilities) != len(r.CapabilitySIDs) {
		return fmt.Errorf("diagnostic capability count mismatch")
	}
	want := map[string]bool{}
	for _, s := range r.CapabilitySIDs {
		want[s] = true
	}
	for _, s := range e.Capabilities {
		if !want[s.SID] || s.Attributes != windows.SE_GROUP_ENABLED {
			return fmt.Errorf("diagnostic capability mismatch")
		}
		delete(want, s.SID)
	}
	if len(want) != 0 || (e.NoAllAppPackages != 0) != r.LPAC {
		return fmt.Errorf("diagnostic LPAC/token mismatch")
	}
	// Verify every original invariant after the exact experimental capability
	// set has independently matched. The strict default verifier is unchanged.
	e.Capabilities = nil
	return verifyToken(e, r.SID)
}

// Diagnostic observation of the launch opt-out claim, not a documented
// replacement for the unsupported class-46 query on Windows build 26200.
func noAllAppPackages(t windows.Token) (uint64, error) {
	b, err := tokenInfo(t, 39)
	if err != nil {
		return 0, err
	}
	defer runtime.KeepAlive(b)
	type attribute struct {
		Name                windows.NTUnicodeString
		ValueType, Reserved uint16
		Flags, Count        uint32
		Values              *uint64
	}
	type attributes struct {
		Version, Reserved uint16
		Count             uint32
		Values            *attribute
	}
	if len(b) < int(unsafe.Sizeof(attributes{})) {
		return 0, fmt.Errorf("short token attribute buffer")
	}
	a := (*attributes)(unsafe.Pointer(&b[0]))
	if a.Count > 1024 {
		return 0, fmt.Errorf("invalid token attribute count")
	}
	for _, v := range unsafe.Slice(a.Values, a.Count) {
		if v.Name.String() == "WIN://NOALLAPPPKG" {
			if v.Count != 1 || v.Values == nil || (v.ValueType != 1 && v.ValueType != 2 && v.ValueType != 6) {
				return 0, fmt.Errorf("invalid NOALLAPPPKG claim")
			}
			return *v.Values, nil
		}
	}
	return 0, nil
}

// Additional token metadata is diagnostic-only; relay authentication continues
// to call InspectToken and its existing strict zero-capability policy.
func inspectProbeToken(t windows.Token) (TokenEvidence, error) {
	e, err := InspectToken(t)
	if err != nil || e.AppContainer == 0 {
		return e, err
	}
	var length uint32
	if err = windows.GetTokenInformation(t, 46, (*byte)(unsafe.Pointer(&e.LessPrivilegedAppContainer)), 4, &length); err != nil {
		e.LPACQueryError = err.Error()
	}
	e.NoAllAppPackages, err = noAllAppPackages(t)
	return e, err
}
