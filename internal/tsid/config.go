package tsid

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Modes.
const (
	ModeAuto     = "auto"
	ModeSystem   = "system"
	ModeEmbedded = "embedded"
	ModeHeaders  = "headers"
)

const defaultUpstream = "http://127.0.0.1:8317"

// Config is the plugin-owned part of plugins.configs.tailscale-identity.
// The host-owned keys (enabled, priority, store) are read but ignored.
type Config struct {
	Mode       string `yaml:"mode"`
	ListenPort int    `yaml:"listen_port"`
	TLS        bool   `yaml:"tls"`
	Upstream   string `yaml:"upstream"`

	// System mode.
	Socket        string `yaml:"socket"`
	UseSocketOnly bool   `yaml:"use_socket_only"`

	// Embedded mode.
	Hostname      string   `yaml:"hostname"`
	StateDir      string   `yaml:"state_dir"`
	AuthKey       string   `yaml:"auth_key"`
	ClientSecret  string   `yaml:"client_secret"`
	AdvertiseTags []string `yaml:"advertise_tags"`
	ControlURL    string   `yaml:"control_url"`
	Ephemeral     bool     `yaml:"ephemeral"`
	UploadLogs    bool     `yaml:"upload_logs"`
	VerboseLogs   bool     `yaml:"verbose_logs"`

	// Identity mapping.
	PrincipalMap map[string]string `yaml:"principal_map"`
	AllowTagged  map[string]string `yaml:"allow_tagged"`
	// RequireMapping defaults to true: logins missing from principal_map get 403.
	RequireMapping *bool `yaml:"require_mapping"`

	// Request policy on the tailnet listener.
	AllowSelf         bool     `yaml:"allow_self"`         // accept requests from this node itself
	ForwardManagement bool     `yaml:"forward_management"` // forward management, resource and OAuth callback paths
	AllowedOrigins    []string `yaml:"allowed_origins"`    // browser origins that may call the proxy
	AllowedHosts      []string `yaml:"allowed_hosts"`      // extra Host names besides the node's own names and IPs
	LogRequests       bool     `yaml:"log_requests"`       // log one line per request with the resolved principal

	// Host-owned keys. Kept so that a strict decoder would not fail.
	Enabled  bool           `yaml:"enabled"`
	Priority int            `yaml:"priority"`
	Store    map[string]any `yaml:"store"`

	upstreamURL *url.URL
}

// Env abstracts the process environment and file system for tests.
type Env struct {
	Getenv    func(string) string
	HomeDir   func() (string, error)
	DirExists func(string) bool
}

// OSEnv is the real process environment.
var OSEnv = Env{
	Getenv:  os.Getenv,
	HomeDir: os.UserHomeDir,
	DirExists: func(p string) bool {
		st, err := os.Stat(p)
		return err == nil && st.IsDir()
	},
}

// ParseConfig decodes config_yaml bytes, applies defaults and validates.
func ParseConfig(raw []byte, env Env) (*Config, error) {
	cfg := &Config{}
	if len(strings.TrimSpace(string(raw))) > 0 {
		if err := yaml.Unmarshal(raw, cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}
	if err := cfg.applyDefaults(env); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults(env Env) error {
	c.Mode = strings.ToLower(strings.TrimSpace(c.Mode))
	if c.Mode == "" {
		c.Mode = ModeAuto
	}
	if c.ListenPort == 0 {
		if c.TLS {
			c.ListenPort = 443
		} else {
			c.ListenPort = 8318
		}
	}
	c.Upstream = strings.TrimSpace(c.Upstream)
	if c.Upstream == "" {
		c.Upstream = defaultUpstream
	}
	c.Hostname = strings.TrimSpace(c.Hostname)
	if c.Hostname == "" {
		c.Hostname = "cliproxy"
	}
	if strings.TrimSpace(c.StateDir) == "" {
		dir, err := defaultStateDir(env)
		if err != nil {
			return err
		}
		c.StateDir = dir
	} else {
		c.StateDir = expandHome(strings.TrimSpace(c.StateDir), env)
	}
	if c.AuthKey == "" {
		c.AuthKey = firstNonEmpty(env.Getenv("TS_AUTHKEY"), env.Getenv("TS_AUTH_KEY"))
	}
	if c.ClientSecret == "" {
		c.ClientSecret = env.Getenv("TS_CLIENT_SECRET")
	}
	c.PrincipalMap = normalizeKeys(c.PrincipalMap, true)
	c.AllowTagged = normalizeKeys(c.AllowTagged, false)
	if c.RequireMapping == nil {
		t := true
		c.RequireMapping = &t
	}
	c.AllowedOrigins = normalizeList(c.AllowedOrigins, func(s string) string { return strings.TrimSuffix(s, "/") })
	c.AllowedHosts = normalizeList(c.AllowedHosts, func(s string) string { return strings.TrimSuffix(s, ".") })
	return nil
}

// MappingRequired reports whether logins must be in principal_map.
func (c *Config) MappingRequired() bool { return c.RequireMapping == nil || *c.RequireMapping }

func (c *Config) validate() error {
	switch c.Mode {
	case ModeAuto, ModeSystem, ModeEmbedded, ModeHeaders:
	default:
		return fmt.Errorf("mode %q: use auto, system, embedded or headers", c.Mode)
	}
	if c.ListenPort < 1 || c.ListenPort > 65535 {
		return fmt.Errorf("listen_port %d is out of range", c.ListenPort)
	}
	u, err := url.Parse(c.Upstream)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("upstream %q: use an http or https URL", c.Upstream)
	}
	c.upstreamURL = u
	for tag, principal := range c.AllowTagged {
		if !strings.HasPrefix(tag, "tag:") {
			return fmt.Errorf("allow_tagged key %q: a tag must start with \"tag:\"", tag)
		}
		if strings.TrimSpace(principal) == "" {
			return fmt.Errorf("allow_tagged %q: principal is empty", tag)
		}
	}
	for login, principal := range c.PrincipalMap {
		if strings.TrimSpace(principal) == "" {
			return fmt.Errorf("principal_map %q: principal is empty", login)
		}
	}
	return nil
}

// UpstreamURL returns the parsed upstream URL.
func (c *Config) UpstreamURL() *url.URL { return c.upstreamURL }

// Equal reports whether two configs would produce the same runtime.
func (c *Config) Equal(o *Config) bool {
	if c == nil || o == nil {
		return c == o
	}
	a, _ := yaml.Marshal(c.comparable())
	b, _ := yaml.Marshal(o.comparable())
	return string(a) == string(b)
}

func (c *Config) comparable() Config {
	cp := *c
	cp.Enabled, cp.Priority, cp.Store, cp.upstreamURL = false, 0, nil, nil
	return cp
}

// ErrNoIdentity and friends explain why a peer gets no principal.
var (
	ErrNoIdentity     = errors.New("peer has no tailnet user identity")
	ErrNotMapped      = errors.New("login is not in principal_map")
	ErrTaggedUnmapped = errors.New("tagged node has no tag in allow_tagged")
)

// PrincipalForLogin maps a user login to a principal.
func (c *Config) PrincipalForLogin(login string) (string, error) {
	key := strings.ToLower(strings.TrimSpace(login))
	if key == "" {
		return "", ErrNoIdentity
	}
	if p, ok := c.PrincipalMap[key]; ok {
		return p, nil
	}
	if c.MappingRequired() {
		return "", ErrNotMapped
	}
	return strings.TrimSpace(login), nil
}

// Principal maps a WhoIs identity to a principal.
func (c *Config) Principal(id Identity) (string, error) {
	if id.Tagged || len(id.Tags) > 0 {
		tags := append([]string(nil), id.Tags...)
		sort.Strings(tags)
		for _, t := range tags {
			if p, ok := c.AllowTagged[t]; ok {
				return p, nil
			}
		}
		return "", ErrTaggedUnmapped
	}
	return c.PrincipalForLogin(id.Login)
}

func defaultStateDir(env Env) (string, error) {
	if env.DirExists("/root/.cli-proxy-api") {
		return "/root/.cli-proxy-api/tailscale", nil
	}
	home, err := env.HomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("state_dir is not set and the home directory is unknown: %v", err)
	}
	return filepath.Join(home, ".cli-proxy-api", "tailscale"), nil
}

func expandHome(p string, env Env) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := env.HomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

func normalizeKeys(m map[string]string, lower bool) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		k = strings.TrimSpace(k)
		if lower {
			k = strings.ToLower(k)
		}
		if k != "" {
			out[k] = strings.TrimSpace(v)
		}
	}
	return out
}

func normalizeList(in []string, f func(string) string) []string {
	var out []string
	for _, v := range in {
		v = f(strings.ToLower(strings.TrimSpace(v)))
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
