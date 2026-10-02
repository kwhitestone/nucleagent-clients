package device

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/nucleagent/nucleagent-shared/a2a"
	"nucleagent-desktop-runner/internal/vault"
)

// UploadArtifact uses a separate run capability and the private device audience.
// The upload URL receives only storage-issued headers, never device/Core keys.
func (c *Client) UploadArtifact(ctx context.Context, credential vault.Credential, request a2a.ExecutionRequest, path string) (a2a.Attachment, error) {
	var empty a2a.Attachment
	if err := c.check(credential); err != nil {
		return empty, err
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > 100<<20 {
		return empty, errors.New("invalid artifact file")
	}
	f, err := os.Open(path)
	if err != nil {
		return empty, errors.New("artifact file unavailable")
	}
	defer f.Close()
	current, err := f.Stat()
	if err != nil || !os.SameFile(before, current) {
		return empty, errors.New("artifact file changed")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(f, (100<<20)+1)); err != nil {
		return empty, err
	}
	if _, err := f.Seek(0, 0); err != nil {
		return empty, err
	}
	var upload struct {
		FileID    string            `json:"fileId"`
		Method    string            `json:"method"`
		UploadURL string            `json:"uploadUrl"`
		Headers   map[string]string `json:"headers"`
	}
	body := map[string]any{"conversationId": request.ConversationID, "stepId": request.StepID, "name": filepath.Base(path), "mimeType": mime.TypeByExtension(filepath.Ext(path)), "size": before.Size()}
	if err := c.callWithArtifact(ctx, "/artifacts/presign", credential.Token, request.ArtifactToken, body, &upload); err != nil {
		return empty, err
	}
	u, err := url.Parse(upload.UploadURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || upload.Method != "PUT" || upload.FileID == "" {
		return empty, errors.New("unsupported artifact upload contract")
	}
	req, err := http.NewRequestWithContext(ctx, "PUT", u.String(), f)
	if err != nil {
		return empty, errors.New("invalid artifact upload")
	}
	req.ContentLength = before.Size()
	for name, value := range upload.Headers {
		if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Cookie") {
			return empty, errors.New("unsupported storage credentials")
		}
		req.Header.Set(name, value)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return empty, errors.New("artifact upload unavailable")
	}
	res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return empty, errors.New("artifact upload rejected")
	}
	var out a2a.Attachment
	if err := c.callWithArtifact(ctx, "/artifacts/complete", credential.Token, request.ArtifactToken, map[string]any{"conversationId": request.ConversationID, "stepId": request.StepID, "fileId": upload.FileID, "sha256": hex.EncodeToString(hash.Sum(nil))}, &out); err != nil {
		return empty, err
	}
	if out.FileID != upload.FileID || out.SHA256 != hex.EncodeToString(hash.Sum(nil)) || out.URL != "" {
		return empty, errors.New("artifact completion mismatch")
	}
	return out, nil
}
