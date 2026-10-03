//go:build windows

package adapter

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nucleagent/nucleagent-shared/a2a"
)

// The optional live package fixture receives its short-lived URL only over
// stdin. It installs through production validation and never starts a model.
func TestWindowsSkillPackageFixture(t *testing.T) {
	if os.Getenv("G9_WINDOWS_SKILL_FIXTURE") != "stdin" {
		t.Skip("requires authorized skill binding over stdin")
	}
	var binding a2a.SkillBindingView
	if err := json.NewDecoder(os.Stdin).Decode(&binding); err != nil {
		t.Fatal("invalid fixture binding")
	}
	root := t.TempDir()
	if base := os.Getenv("G9_WINDOWS_EVIDENCE_ROOT"); base != "" {
		var err error
		root, err = os.MkdirTemp(base, "skill-package-")
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := InstallSkills(context.Background(), root, []a2a.SkillBindingView{binding}); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(root, "workspace", ".agents", "skills", binding.Slug, "SKILL.md")
	content, err := os.ReadFile(entry)
	if err != nil || len(content) == 0 {
		t.Fatal("skill entrypoint missing")
	}
	t.Logf("installedEntry=%s bytes=%d", entry, len(content))
}
