//go:build windows

package isolation

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestVerifyRejectsWeakenedTokens(t *testing.T) {
	sid := "S-1-5-21-1-2-3-4"
	valid := func() TokenEvidence {
		return TokenEvidence{Restricted: []Group{{SID: sid}}, Integrity: "S-1-16-4096", MandatoryPolicy: 1, HasRestrictions: 1}
	}
	if err := verifyToken(valid(), sid); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*TokenEvidence){
		"wrong task":           func(e *TokenEvidence) { e.Restricted = []Group{{SID: "S-1-5-21-5-6-7-8"}} },
		"no restrictions":      func(e *TokenEvidence) { e.Restricted = nil },
		"everyone restriction": func(e *TokenEvidence) { e.Restricted = append(e.Restricted, Group{SID: "S-1-1-0"}) },
		"medium IL":            func(e *TokenEvidence) { e.Integrity = "S-1-16-8192" },
		"write up":             func(e *TokenEvidence) { e.MandatoryPolicy = 0 },
		"elevated":             func(e *TokenEvidence) { e.Elevated = 1 },
		"debug privilege": func(e *TokenEvidence) {
			e.Privileges = []windows.LUIDAndAttributes{{Luid: windows.LUID{LowPart: 20}, Attributes: windows.SE_PRIVILEGE_ENABLED}}
		},
		"enabled administrators": func(e *TokenEvidence) {
			e.Groups = []Group{{SID: "S-1-5-32-544", Attributes: windows.SE_GROUP_ENABLED}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := valid()
			mutate(&e)
			if verifyToken(e, sid) == nil {
				t.Fatal("unsafe token accepted")
			}
		})
	}
	packageSID := "S-1-15-2-1-2-3-4-5-6-7"
	e := valid()
	e.Restricted = nil
	e.AppContainer = 1
	e.Package = packageSID
	if err := verifyToken(e, packageSID); err != nil {
		t.Fatal(err)
	}
	e.Package = "S-1-15-2-7-6-5-4-3-2-1"
	if verifyToken(e, packageSID) == nil {
		t.Fatal("foreign package accepted")
	}
}

func TestNativeRestrictedACL(t *testing.T) {
	root := t.TempDir()
	sid, err := newSID()
	if err != nil {
		t.Fatal(err)
	}
	if err = SetProbeACL(root, sid.String(), false); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"workspace", "control"} {
		p := filepath.Join(root, dir)
		if err = os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
		aclSID := sid.String()
		if dir == "control" {
			aclSID = ""
		}
		if err = SetProbeACL(p, aclSID, dir == "workspace"); err != nil {
			t.Fatal(err)
		}
	}
	token, err := restrictedToken(sid, false)
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	e, err := InspectToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyToken(e, sid.String()); err != nil {
		t.Fatal(err)
	}
	observations, err := accessProbe(token, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range observations {
		if o.Object == filepath.Join(root, "workspace", "access-probe.txt") {
			if !o.Allowed {
				t.Fatalf("workspace not writable: %+v", o)
			}
		} else if o.Object == filepath.Join(root, "control", "sensitive-canary.txt") || o.Object == filepath.Join(root, "control", "outside.txt") {
			if o.Allowed {
				t.Fatalf("control boundary crossed: %+v", o)
			}
		}
	}
}

func TestRejectReparsePath(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	link := filepath.Join(root, "link")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("host cannot create test symlink: %v", err)
	}
	if checkPath(link) == nil {
		t.Fatal("reparse path accepted")
	}
}
