package tsid

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Version is the plugin version reported in metadata. Release builds set it
// with -ldflags "-X github.com/1fc0nfig/cliproxy-tailscale/internal/tsid.Version=<version>"
// so it matches the GitHub release tag. Keep the default dotted numeric.
var Version = "0.0.0-dev"

// Plugin identity.
const (
	PluginID      = "tailscale-identity"
	SchemaVersion = 6
	stopTimeout   = 10 * time.Second
)

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Plugin holds the state of one loaded plugin image.
type Plugin struct {
	deps   Deps
	env    Env
	secret string

	lifecycle sync.Mutex // serializes register, quiesce and shutdown

	mu      sync.RWMutex
	cfg     *Config
	rt      *Runtime
	closed  bool
	resBase string
}

// NewPlugin returns a plugin with a fresh random per-boot secret.
func NewPlugin(deps Deps, env Env) *Plugin {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return &Plugin{deps: deps, env: env, secret: hex.EncodeToString(b)}
}

// Reopen clears the closed flag after a new cliproxy_plugin_init.
func (p *Plugin) Reopen() {
	p.mu.Lock()
	p.closed = false
	p.mu.Unlock()
}

// Handle dispatches one RPC call and returns the JSON envelope.
func (p *Plugin) Handle(method string, req []byte) []byte {
	var (
		res any
		err error
	)
	switch method {
	case "plugin.register", "plugin.reconfigure":
		res, err = p.register(req)
	case "plugin.quiesce":
		p.stopRuntime()
		res = struct{}{}
	case "frontend_auth.identifier":
		res = map[string]string{"identifier": PluginID}
	case "frontend_auth.authenticate":
		res, err = p.authenticate(req)
	case "management.register":
		res, err = p.managementRegister(req)
	case "management.handle":
		res, err = p.managementHandle(req)
	default:
		return errEnvelope("unknown_method", "unknown method: "+method)
	}
	if err != nil {
		return errEnvelope("plugin_error", err.Error())
	}
	raw, err := json.Marshal(res)
	if err != nil {
		return errEnvelope("plugin_error", err.Error())
	}
	out, _ := json.Marshal(envelope{OK: true, Result: raw})
	return out
}

func errEnvelope(code, msg string) []byte {
	out, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: msg}})
	return out
}

type registerRequest struct {
	ConfigYAML    []byte `json:"config_yaml"`
	SchemaVersion int    `json:"schema_version"`
}

func (p *Plugin) register(req []byte) (any, error) {
	var r registerRequest
	if len(req) > 0 {
		if err := json.Unmarshal(req, &r); err != nil {
			return nil, fmt.Errorf("decode register request: %w", err)
		}
	}
	cfg, err := ParseConfig(r.ConfigYAML, p.env)
	if err != nil {
		return nil, err
	}
	p.lifecycle.Lock()
	defer p.lifecycle.Unlock()
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, fmt.Errorf("plugin is shut down")
	}
	old, oldCfg := p.rt, p.cfg
	if old != nil && oldCfg.Equal(cfg) && !old.Failed() {
		p.cfg = cfg
		p.mu.Unlock()
		return registration(), nil
	}
	p.rt = nil
	p.mu.Unlock()

	// Stop the old runtime first so the port and the state dir are free.
	if old != nil {
		old.Stop(stopTimeout)
	}
	rt := StartRuntime(cfg, p.secret, p.deps)
	p.mu.Lock()
	p.cfg, p.rt = cfg, rt
	p.mu.Unlock()
	return registration(), nil
}

// stopRuntime stops background work and keeps the config (quiesce).
func (p *Plugin) stopRuntime() {
	p.lifecycle.Lock()
	defer p.lifecycle.Unlock()
	p.mu.Lock()
	rt := p.rt
	p.rt = nil
	p.mu.Unlock()
	if rt != nil {
		rt.Stop(stopTimeout)
	}
}

// Shutdown stops everything. It is idempotent.
func (p *Plugin) Shutdown() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	p.stopRuntime()
}

type configField struct {
	Name        string   `json:"Name"`
	Type        string   `json:"Type"`
	EnumValues  []string `json:"EnumValues,omitempty"`
	Description string   `json:"Description,omitempty"`
}

type metadata struct {
	Name             string        `json:"Name"`
	Version          string        `json:"Version"`
	Author           string        `json:"Author"`
	GitHubRepository string        `json:"GitHubRepository"`
	Logo             string        `json:"Logo"`
	ConfigFields     []configField `json:"ConfigFields"`
}

type registrationResult struct {
	SchemaVersion int             `json:"schema_version"`
	Metadata      metadata        `json:"metadata"`
	Capabilities  map[string]bool `json:"capabilities"`
}

func registration() registrationResult {
	return registrationResult{
		SchemaVersion: SchemaVersion,
		Metadata: metadata{
			Name:             PluginID,
			Version:          Version,
			Author:           "1fc0nfig",
			GitHubRepository: "https://github.com/1fc0nfig/cliproxy-tailscale",
			ConfigFields: []configField{
				{Name: "mode", Type: "enum", EnumValues: []string{ModeAuto, ModeSystem, ModeEmbedded, ModeHeaders}, Description: "auto picks system when a tailscaled LocalAPI exists, else embedded"},
				{Name: "listen_port", Type: "integer", Description: "tailnet port (default 443 with tls, else 8318)"},
				{Name: "tls", Type: "boolean", Description: "serve HTTPS with the tailnet certificate"},
				{Name: "upstream", Type: "string", Description: "CLIProxyAPI URL (default http://127.0.0.1:8317)"},
				{Name: "hostname", Type: "string", Description: "embedded node name (default cliproxy)"},
				{Name: "state_dir", Type: "string", Description: "embedded node state directory"},
				{Name: "auth_key", Type: "string", Description: "embedded auth key (or TS_AUTHKEY)"},
				{Name: "client_secret", Type: "string", Description: "embedded OAuth client secret (or TS_CLIENT_SECRET)"},
				{Name: "advertise_tags", Type: "array", Description: "tags for OAuth-minted keys"},
				{Name: "socket", Type: "string", Description: "tailscaled socket path (system mode)"},
				{Name: "use_socket_only", Type: "boolean", Description: "skip the macOS GUI LocalAPI discovery"},
				{Name: "principal_map", Type: "object", Description: "login -> principal"},
				{Name: "allow_tagged", Type: "object", Description: "tag -> principal for tagged nodes"},
				{Name: "require_mapping", Type: "boolean", Description: "reject logins missing from principal_map (default true)"},
				{Name: "allow_self", Type: "boolean", Description: "accept requests from this node itself (default false)"},
				{Name: "forward_management", Type: "boolean", Description: "forward management and OAuth callback paths (default false)"},
				{Name: "allowed_origins", Type: "array", Description: "browser origins allowed to call the proxy (default none)"},
				{Name: "allowed_hosts", Type: "array", Description: "extra Host names besides the node names and IPs"},
				{Name: "log_requests", Type: "boolean", Description: "log the resolved principal of each request"},
			},
		},
		Capabilities: map[string]bool{
			"frontend_auth_provider": true,
			"management_api":         true,
		},
	}
}

type frontendAuthRequest struct {
	Method  string              `json:"Method"`
	Path    string              `json:"Path"`
	Headers map[string][]string `json:"Headers"`
	// Body is left raw: the plugin never needs it, so skip the base64 decode.
	Body json.RawMessage `json:"Body"`
}

func (p *Plugin) authenticate(req []byte) (any, error) {
	var r frontendAuthRequest
	if err := json.Unmarshal(req, &r); err != nil {
		return nil, fmt.Errorf("decode authenticate request: %w", err)
	}
	p.mu.RLock()
	cfg, rt, closed := p.cfg, p.rt, p.closed
	p.mu.RUnlock()
	if closed {
		return AuthResult{}, nil
	}
	mode := ""
	if rt != nil {
		mode = rt.Mode()
	}
	res := Authenticate(cfg, p.secret, mode, CanonicalHeader(r.Headers))
	if res.Authenticated && cfg.LogRequests {
		Logf("info", "tailscale-identity: frontend auth", map[string]any{
			"principal": maskPrincipal(res.Principal), "mode": res.Metadata["mode"], "method": r.Method, "path": r.Path})
	}
	return res, nil
}

// Report returns the current status for management.
func (p *Plugin) Report(ctx context.Context) StatusReport {
	p.mu.RLock()
	cfg, rt := p.cfg, p.rt
	p.mu.RUnlock()
	if rt != nil {
		return rt.Report(ctx)
	}
	rep := StatusReport{Mode: "stopped", TailnetIPs: []string{}, Listen: []string{}}
	if cfg != nil {
		rep.ConfiguredMode, rep.Upstream, rep.TLS = cfg.Mode, cfg.Upstream, cfg.TLS
	}
	return rep
}
