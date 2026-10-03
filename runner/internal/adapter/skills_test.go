package adapter

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSkillArchiveRejectsTraversalLinksAndCaseCollisions(t *testing.T) {
	for _, scenario := range []string{"traversal", "link", "case", "missing", "valid"} {
		t.Run(scenario, func(t *testing.T) {
			var buffer bytes.Buffer
			writer := zip.NewWriter(&buffer)
			if scenario != "missing" {
				f, _ := writer.Create("SKILL.md")
				_, _ = f.Write([]byte("# Offline skill"))
			}
			name := "reference.txt"
			if scenario == "traversal" {
				name = "../outside.txt"
			}
			if scenario == "case" {
				name = "skill.md"
			}
			header := &zip.FileHeader{Name: name, Method: zip.Deflate}
			if scenario == "link" {
				header.SetMode(os.ModeSymlink | 0777)
			}
			f, _ := writer.CreateHeader(header)
			_, _ = f.Write([]byte("reference"))
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			err := extractSkill(filepath.Join(root, "skill"), buffer.Bytes())
			if (err == nil) != (scenario == "valid") {
				t.Fatalf("scenario %s: %v", scenario, err)
			}
			if _, err := os.Stat(filepath.Join(root, "outside.txt")); !os.IsNotExist(err) {
				t.Fatal("archive escaped destination")
			}
		})
	}
}

func TestSkillArchiveSelectedSlugWrapper(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		entries []string
		ok      bool
	}{
		{"root", []string{"SKILL.md", "references/input.txt"}, true},
		{"wrapped", []string{"selected/", "selected/SKILL.md", "selected/references/input.txt"}, true},
		{"wrong-slug", []string{"other/SKILL.md"}, false},
		{"mixed-roots", []string{"selected/SKILL.md", "other/input.txt"}, false},
		{"traversal", []string{"selected/SKILL.md", "selected/../outside.txt"}, false},
		{"case-collision", []string{"selected/SKILL.md", "selected/skill.md"}, false},
		{"nested-wrapper", []string{"selected/nested/SKILL.md"}, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var buffer bytes.Buffer
			writer := zip.NewWriter(&buffer)
			for _, name := range scenario.entries {
				f, err := writer.Create(name)
				if err != nil {
					t.Fatal(err)
				}
				if name[len(name)-1] != '/' {
					if _, err := f.Write([]byte("# Offline fixture")); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			destination := filepath.Join(root, "selected")
			err := extractSkill(destination, buffer.Bytes())
			if (err == nil) != scenario.ok {
				t.Fatalf("extract result: %v", err)
			}
			if scenario.ok {
				data, err := os.ReadFile(filepath.Join(destination, "SKILL.md"))
				if err != nil || string(data) != "# Offline fixture" {
					t.Fatalf("entrypoint: %q %v", data, err)
				}
			}
			if _, err := os.Stat(filepath.Join(root, "outside.txt")); !os.IsNotExist(err) {
				t.Fatal("archive escaped destination")
			}
		})
	}
}
