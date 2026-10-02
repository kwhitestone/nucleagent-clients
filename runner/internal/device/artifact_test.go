package device

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/nucleagent/nucleagent-shared/a2a"
	"nucleagent-desktop-runner/internal/vault"
)

func TestArtifactUploadSeparatesDeviceAndStorageCredentials(t *testing.T) {
	content := []byte("generated offline artifact")
	hash := sha256.Sum256(content)
	digest := hex.EncodeToString(hash[:])
	var origin string
	var uploads int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/store" {
			if r.Header.Get("Authorization") != "" || r.Header.Get("X-Artifact-Token") != "" || r.Header.Get("X-Executor-Token") != "" {
				t.Error("credential leaked to storage")
			}
			data, _ := io.ReadAll(r.Body)
			if string(data) != string(content) || r.Method != "PUT" {
				t.Error("wrong stored bytes")
			}
			uploads++
			w.WriteHeader(204)
			return
		}
		if r.Header.Get("Authorization") != "Bearer pcd_fixture" || r.Header.Get("X-Artifact-Token") != "run-fixture" {
			t.Error("missing device/run authorization")
		}
		var out any
		switch r.URL.Path {
		case a2a.PCNativePath + "/artifacts/presign":
			out = map[string]any{"fileId": "file", "method": "PUT", "uploadUrl": origin + "/store", "headers": map[string]string{"Content-Type": "text/plain"}}
		case a2a.PCNativePath + "/artifacts/complete":
			var in struct {
				SHA256 string `json:"sha256"`
			}
			if json.NewDecoder(r.Body).Decode(&in) != nil || in.SHA256 != digest || uploads != 1 {
				t.Error("invalid completion ordering or hash")
			}
			out = a2a.Attachment{FileID: "file", SHA256: digest, Name: "result.txt"}
		default:
			t.Error("unexpected endpoint")
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": out})
	}))
	defer server.Close()
	origin = server.URL
	client, err := New(origin)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.http = server.Client()
	path := filepath.Join(t.TempDir(), "result.txt")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := client.UploadArtifact(context.Background(), vault.Credential{CoreOrigin: origin, Token: "pcd_fixture", DeviceID: "device", InstanceID: "instance"}, a2a.ExecutionRequest{ConversationID: 1, StepID: "step", ArtifactToken: "run-fixture"}, path)
	if err != nil || result.FileID != "file" || result.SHA256 != digest {
		t.Fatalf("upload: %+v %v", result, err)
	}
}
