// Package device implements the private device audience. It never accepts a
// server executor token or forwards browser session credentials to a worker.
package device

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nucleagent/nucleagent-shared/a2a"
	"nucleagent-desktop-runner/internal/vault"
)

var ErrPending = errors.New("device binding awaits user confirmation")
var ErrUnauthorized = errors.New("device credential expired or revoked")

type Client struct {
	origin string
	http   *http.Client
}
type Binding struct {
	Challenge a2a.PCBindChallenge
	private   ed25519.PrivateKey
}

func Origin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.Path != "" && u.Path != "/" {
		return "", errors.New("Core must be an HTTPS origin")
	}
	return strings.TrimRight(u.String(), "/"), nil
}
func New(origin string) (*Client, error) {
	base, err := Origin(origin)
	if err != nil {
		return nil, err
	}
	return &Client{origin: base, http: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) Close() { c.http.CloseIdleConnections() }
func (c *Client) call(ctx context.Context, route, token string, input, output any) error {
	return c.callWithArtifact(ctx, route, token, "", input, output)
}
func (c *Client) callWithArtifact(ctx context.Context, route, token, artifact string, input, output any) error {
	data, err := json.Marshal(input)
	if err != nil {
		return errors.New("invalid device request")
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.origin+a2a.PCNativePath+route, bytes.NewReader(data))
	if err != nil {
		return errors.New("invalid device endpoint")
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if artifact != "" {
		req.Header.Set("X-Artifact-Token", artifact)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return errors.New("device transport unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusAccepted {
		return ErrPending
	}
	if res.StatusCode == 401 || res.StatusCode == 403 {
		return ErrUnauthorized
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("device request rejected (HTTP %d)", res.StatusCode)
	}
	data, err = io.ReadAll(io.LimitReader(res.Body, 16385))
	if err != nil || len(data) > 16384 {
		return errors.New("device response exceeds bounds")
	}
	var envelope struct {
		Code int             `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(data, &envelope) != nil || envelope.Code != 0 || len(envelope.Data) == 0 {
		return errors.New("invalid device response")
	}
	if output != nil && json.Unmarshal(envelope.Data, output) != nil {
		return errors.New("invalid device response data")
	}
	return nil
}
func (c *Client) Begin(ctx context.Context, name, osName, arch string) (*Binding, error) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	b := &Binding{private: private}
	err = c.call(ctx, "/bind/start", "", a2a.PCBindStart{PublicKey: base64.StdEncoding.EncodeToString(pub), Name: name, OS: osName, Arch: arch}, &b.Challenge)
	if err != nil {
		return nil, err
	}
	if b.Challenge.ID == "" || len(b.Challenge.Nonce) < 32 || len(b.Challenge.Nonce) > 128 || b.Challenge.UserCode == "" || !b.Challenge.ExpiresAt.After(time.Now()) || b.Challenge.ExpiresAt.After(time.Now().Add(11*time.Minute)) {
		return nil, errors.New("invalid binding challenge")
	}
	return b, nil
}
func (c *Client) Finish(ctx context.Context, b *Binding) (vault.Credential, error) {
	if b == nil || len(b.private) != ed25519.PrivateKeySize || !b.Challenge.ExpiresAt.After(time.Now()) {
		return vault.Credential{}, errors.New("binding challenge expired")
	}
	message := "nucleagent-bind-v1\n" + b.Challenge.ID + "\n" + b.Challenge.Nonce
	var out a2a.PCDeviceCredential
	err := c.call(ctx, "/bind/finish", "", a2a.PCBindFinish{ID: b.Challenge.ID, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(b.private, []byte(message)))}, &out)
	if err != nil {
		return vault.Credential{}, err
	}
	if !validCredential(out) {
		return vault.Credential{}, errors.New("invalid scoped credential")
	}
	return vault.Credential{DeviceID: out.DeviceID, InstanceID: out.InstanceID, Token: out.Token, PrivateKey: base64.StdEncoding.EncodeToString(b.private), CoreOrigin: c.origin, Version: out.Version, ExpiresAt: out.ExpiresAt}, nil
}
func validCredential(c a2a.PCDeviceCredential) bool {
	return strings.HasPrefix(c.DeviceID, "pc-") && strings.HasPrefix(c.InstanceID, "pc-") && strings.HasPrefix(c.Token, "pcd_") && len(c.Token) >= 40 && c.Version > 0 && c.ExpiresAt.After(time.Now())
}
func (c *Client) check(v vault.Credential) error {
	if v.CoreOrigin != c.origin || !strings.HasPrefix(v.Token, "pcd_") || v.DeviceID == "" || v.InstanceID == "" {
		return errors.New("device scope mismatch")
	}
	return nil
}
func (c *Client) Renew(ctx context.Context, v vault.Credential) (vault.Credential, error) {
	if err := c.check(v); err != nil {
		return vault.Credential{}, err
	}
	key, err := base64.StdEncoding.DecodeString(v.PrivateKey)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return vault.Credential{}, errors.New("invalid installation key")
	}
	now := time.Now().Unix()
	hash := sha256.Sum256([]byte(v.Token))
	message := fmt.Sprintf("nucleagent-renew-v1\n%s\n%d\n%d\n%s", v.DeviceID, v.Version, now, hex.EncodeToString(hash[:]))
	var out a2a.PCDeviceCredential
	if err = c.call(ctx, "/renew", v.Token, a2a.PCRenewRequest{Timestamp: now, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(message)))}, &out); err != nil {
		return vault.Credential{}, err
	}
	if !validCredential(out) || out.DeviceID != v.DeviceID || out.InstanceID != v.InstanceID || out.Version != v.Version+1 {
		return vault.Credential{}, errors.New("renewal identity mismatch")
	}
	v.Token = out.Token
	v.Version = out.Version
	v.ExpiresAt = out.ExpiresAt
	return v, nil
}
func (c *Client) Register(ctx context.Context, v vault.Credential) (string, error) {
	if err := c.check(v); err != nil {
		return "", err
	}
	var out a2a.PCRegistration
	if err := c.call(ctx, "/register", v.Token, struct{}{}, &out); err != nil {
		return "", err
	}
	u, err := url.Parse(out.WSURL)
	base, _ := url.Parse(c.origin)
	if err != nil || u.Scheme != "wss" || u.Host != base.Host || u.Path != a2a.PCNativePath+"/ws" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || out.DeviceID != v.DeviceID || out.InstanceID != v.InstanceID || out.PCContract != a2a.PCContractV1 {
		return "", errors.New("registration contract or origin mismatch")
	}
	return u.String(), nil
}
func (c *Client) Revoke(ctx context.Context, v vault.Credential) error {
	if err := c.check(v); err != nil {
		return err
	}
	return c.call(ctx, "/revoke", v.Token, struct{}{}, nil)
}
