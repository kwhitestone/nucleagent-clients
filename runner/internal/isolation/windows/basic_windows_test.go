//go:build windows

package isolation

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/windows"
)

// This regression documents the candidate's limitation. An ordinary same-user
// Low IL ACL grant remains writable; a scoped explicit deny blocks writes.
// Passing this test does not constitute sandbox acceptance.
func TestBasicACLRequiresExplicitDeny(t *testing.T) {
	root := t.TempDir()
	allowed := filepath.Join(root, "public-low")
	denied := filepath.Join(root, "acl-denied-low")
	if err := os.Mkdir(allowed, 0700); err != nil {
		t.Fatal(err)
	}
	if err := SetProbeACL(allowed, "S-1-1-0", true); err != nil {
		t.Fatal(err)
	}
	if err := prepareBasicDeniedCanary(denied); err != nil {
		t.Fatal(err)
	}
	// Restore the disposable deny before TempDir cleanup; GENERIC_WRITE also
	// denies SYNCHRONIZE, which Go's directory removal requests on Windows.
	t.Cleanup(func() {
		if err := SetProbeACL(denied, "", true); err != nil {
			t.Error(err)
		}
	})
	token, err := restrictedToken(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	var imp windows.Token
	if err := windows.DuplicateTokenEx(token, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &imp); err != nil {
		t.Fatal(err)
	}
	defer imp.Close()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.SetThreadToken(nil, imp); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := windows.RevertToSelf(); err != nil {
			panic("test cannot revert token")
		}
	}()
	for _, tc := range []struct {
		path    string
		allowed bool
	}{
		{filepath.Join(allowed, "outside.txt"), true},
		{filepath.Join(denied, "outside.txt"), false},
	} {
		p, err := windows.UTF16PtrFromString(tc.path)
		if err != nil {
			t.Fatal(err)
		}
		h, err := windows.CreateFile(p, windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err == nil {
			windows.CloseHandle(h)
		}
		if (tc.allowed && err != nil) || (!tc.allowed && err != windows.ERROR_ACCESS_DENIED) {
			t.Fatalf("%s: allowed=%v error=%v", tc.path, tc.allowed, err)
		}
	}
}

func TestBasicTokenNative(t *testing.T) {
	token, err := restrictedToken(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	e, err := InspectToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyBasicToken(e); err != nil {
		t.Fatal(err)
	}
	if len(e.Restricted) != 0 || e.AppContainer != 0 {
		t.Fatal("B' contains a restricting SID or AppContainer")
	}
	for _, name := range []string{"SeDebugPrivilege", "SeTakeOwnershipPrivilege", "SeLoadDriverPrivilege", "SeBackupPrivilege", "SeRestorePrivilege", "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeTcbPrivilege", "SeSecurityPrivilege"} {
		p, err := windows.UTF16PtrFromString(name)
		if err != nil {
			t.Fatal(err)
		}
		var luid windows.LUID
		if err = windows.LookupPrivilegeValue(nil, p, &luid); err != nil {
			t.Fatal(err)
		}
		for _, retained := range e.Privileges {
			if retained.Luid == luid {
				t.Fatalf("retained dangerous privilege %s", name)
			}
		}
	}
}

func TestBasicTokenRejectsWrongIdentity(t *testing.T) {
	valid := func() TokenEvidence {
		return TokenEvidence{Integrity: "S-1-16-4096", MandatoryPolicy: 1, HasRestrictions: 1, Groups: []Group{{SID: "S-1-5-32-544", Attributes: windows.SE_GROUP_USE_FOR_DENY_ONLY}}}
	}
	if err := verifyBasicToken(valid()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*TokenEvidence){
		"restricted SID":                    func(e *TokenEvidence) { e.Restricted = []Group{{SID: "S-1-5-21-1-2-3-4"}} },
		"capability":                        func(e *TokenEvidence) { e.Capabilities = []Group{{SID: "S-1-15-3-1"}} },
		"medium":                            func(e *TokenEvidence) { e.Integrity = "S-1-16-8192" },
		"elevation":                         func(e *TokenEvidence) { e.Elevated = 1 },
		"disabled admin without deny-only":  func(e *TokenEvidence) { e.Groups[0].Attributes = 0 },
		"enabled admin":                     func(e *TokenEvidence) { e.Groups[0].Attributes = windows.SE_GROUP_ENABLED },
		"dangerous privilege even disabled": func(e *TokenEvidence) { e.Privileges = []windows.LUIDAndAttributes{{Luid: windows.LUID{LowPart: 20}}} },
	} {
		t.Run(name, func(t *testing.T) {
			e := valid()
			mutate(&e)
			if verifyBasicToken(e) == nil {
				t.Fatal("invalid B' token accepted")
			}
		})
	}
}

func TestBasicDesktopNative(t *testing.T) {
	sid, err := newSID()
	if err != nil {
		t.Fatal(err)
	}
	d, err := privateDesktop(sid.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := d.close(); err != nil {
			t.Error(err)
		}
	}()
	name, err := userObjectName(uintptr(d.desk))
	if err != nil || name != "worker" {
		t.Fatalf("desktop name %q: %v", name, err)
	}
	station, err := userObjectName(uintptr(d.station))
	if err != nil || station+`\`+name != d.name {
		t.Fatalf("station %q: %v", station, err)
	}
}

func TestBasicCandidateCannotMixModes(t *testing.T) {
	r := ProbeHome("", "", nil, false, true, false, false, false, false, "dos", CompatibilityOptions{BasicToken: true})
	if r.Error == "" || r.Root != "" || r.Resumed {
		t.Fatal("mixed mode reached preparation")
	}
}
