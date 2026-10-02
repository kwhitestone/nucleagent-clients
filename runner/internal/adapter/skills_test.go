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
