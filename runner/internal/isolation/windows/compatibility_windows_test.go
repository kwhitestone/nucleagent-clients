//go:build windows

package isolation

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestCompatibilityCannotRelaxTokenBoundary(t *testing.T) {
	caps, err := compatibilityCapabilities([]string{"codeGeneration"})
	if err != nil {
		t.Fatal(err)
	}
	r := &ProbeResult{SID: "S-1-15-2-1-2-3-4-5-6-7", CompatibilityOptions: CompatibilityOptions{LPAC: true}, CapabilitySIDs: []string{caps[0].Sid.String()}}
	valid := func() TokenEvidence {
		return TokenEvidence{Package: r.SID, AppContainer: 1, Integrity: "S-1-16-4096", MandatoryPolicy: 1, HasRestrictions: 1, NoAllAppPackages: 1, Capabilities: []Group{{SID: r.CapabilitySIDs[0], Attributes: windows.SE_GROUP_ENABLED}}}
	}
	if err = verifyCompatibilityToken(valid(), r); err != nil {
		t.Fatal(err)
	}
	if verifyToken(valid(), r.SID) == nil {
		t.Fatal("diagnostic capability escaped strict verifier")
	}
	for name, mutate := range map[string]func(*TokenEvidence){
		"foreign package": func(e *TokenEvidence) { e.Package = "S-1-15-2-7-6-5-4-3-2-1" },
		"extra network capability": func(e *TokenEvidence) {
			e.Capabilities = append(e.Capabilities, Group{SID: "S-1-15-3-1", Attributes: windows.SE_GROUP_ENABLED})
		},
		"wrong capability":    func(e *TokenEvidence) { e.Capabilities[0].SID = "S-1-15-3-1" },
		"disabled capability": func(e *TokenEvidence) { e.Capabilities[0].Attributes = 0 },
		"missing LPAC claim":  func(e *TokenEvidence) { e.NoAllAppPackages = 0 },
		"elevated":            func(e *TokenEvidence) { e.Elevated = 1 },
		"medium IL":           func(e *TokenEvidence) { e.Integrity = "S-1-16-8192" },
		"write up":            func(e *TokenEvidence) { e.MandatoryPolicy = 0 },
		"debug privilege":     func(e *TokenEvidence) { e.Privileges = []windows.LUIDAndAttributes{{Luid: windows.LUID{LowPart: 20}}} },
	} {
		t.Run(name, func(t *testing.T) {
			e := valid()
			mutate(&e)
			if verifyCompatibilityToken(e, r) == nil {
				t.Fatal("unsafe diagnostic token accepted")
			}
		})
	}
	for _, names := range [][]string{{"internetClient"}, {"broadFileSystemAccess"}, {"codeGeneration", "codeGeneration"}, {"unknown"}} {
		if _, err = compatibilityCapabilities(names); err == nil {
			t.Fatalf("unapproved capabilities accepted: %v", names)
		}
	}
}
