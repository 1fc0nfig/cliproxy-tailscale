package tsid

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func testEnv(vars map[string]string) Env {
	return Env{
		Getenv:    func(k string) string { return vars[k] },
		HomeDir:   func() (string, error) { return "/home/u", nil },
		DirExists: func(string) bool { return false },
	}
}

func mustConfig(t *testing.T, y string) *Config {
	t.Helper()
	cfg, err := ParseConfig([]byte(y), testEnv(nil))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	return cfg
}

func TestConfigDefaults(t *testing.T) {
	cfg, err := ParseConfig([]byte("enabled: true\npriority: 10\n"), testEnv(map[string]string{"TS_AUTHKEY": "k1", "TS_CLIENT_SECRET": "s1"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeAuto || cfg.ListenPort != 8318 || cfg.Upstream != defaultUpstream || cfg.Hostname != "cliproxy" {
		t.Fatalf("defaults: %+v", cfg)
	}
	if cfg.StateDir != "/home/u/.cli-proxy-api/tailscale" {
		t.Fatalf("state_dir: %s", cfg.StateDir)
	}
	if cfg.AuthKey != "k1" || cfg.ClientSecret != "s1" {
		t.Fatalf("env fallback: %q %q", cfg.AuthKey, cfg.ClientSecret)
	}
	tlsCfg := mustConfig(t, "tls: true\n")
	if tlsCfg.ListenPort != 443 {
		t.Fatalf("tls port: %d", tlsCfg.ListenPort)
	}
	env := testEnv(nil)
	env.DirExists = func(p string) bool { return p == "/root/.cli-proxy-api" }
	docker, _ := ParseConfig(nil, env)
	if docker.StateDir != "/root/.cli-proxy-api/tailscale" {
		t.Fatalf("docker state_dir: %s", docker.StateDir)
	}
}

func TestConfigValidation(t *testing.T) {
	for _, y := range []string{
		"mode: magic\n",
		"upstream: ftp://x\n",
		"listen_port: 70000\n",
		"allow_tagged:\n  server: svc\n",
		"principal_map:\n  a@b: \"\"\n",
	} {
		if _, err := ParseConfig([]byte(y), testEnv(nil)); err == nil {
			t.Errorf("expected error for %q", y)
		}
	}
}

func TestPrincipalMapping(t *testing.T) {
	cfg := mustConfig(t, `
require_mapping: false
principal_map:
  Alice@GitHub: alice
allow_tagged:
  tag:ci: ci-bot
  tag:build: build-bot
`)
	cases := []struct {
		name string
		id   Identity
		want string
		err  error
	}{
		{"mapped, case-insensitive", Identity{Login: "alice@github"}, "alice", nil},
		{"unmapped falls back to login", Identity{Login: "bob@github"}, "bob@github", nil},
		{"no login", Identity{}, "", ErrNoIdentity},
		{"tagged mapped", Identity{Tagged: true, Tags: []string{"tag:x", "tag:ci"}}, "ci-bot", nil},
		{"tagged picks sorted first", Identity{Tagged: true, Tags: []string{"tag:ci", "tag:build"}}, "build-bot", nil},
		{"tagged unmapped", Identity{Tagged: true, Tags: []string{"tag:x"}, Login: "tagged-devices"}, "", ErrTaggedUnmapped},
	}
	for _, c := range cases {
		got, err := cfg.Principal(c.id)
		if got != c.want || !errors.Is(err, c.err) {
			t.Errorf("%s: got %q, %v; want %q, %v", c.name, got, err, c.want, c.err)
		}
	}
	strict := mustConfig(t, "principal_map:\n  alice@github: alice\n") // require_mapping defaults to true
	if _, err := strict.Principal(Identity{Login: "bob@github"}); !errors.Is(err, ErrNotMapped) {
		t.Fatalf("require_mapping: %v", err)
	}
	if p, _ := strict.Principal(Identity{Login: "alice@github"}); p != "alice" {
		t.Fatalf("require_mapping mapped: %q", p)
	}
}

func TestSecretMatches(t *testing.T) {
	if !SecretMatches("abc", "abc") {
		t.Fatal("equal")
	}
	for _, g := range []string{"", "abd", "ab", "abcd"} {
		if SecretMatches(g, "abc") {
			t.Fatalf("matched %q", g)
		}
	}
	if SecretMatches("", "") {
		t.Fatal("empty secret must never match")
	}
}

func TestAuthenticate(t *testing.T) {
	cfg := mustConfig(t, "mode: system\n")
	secret := strings.Repeat("a", 64)
	ok := map[string][]string{
		"x-cpa-tailnet-secret":    {secret},
		"X-Cpa-Tailnet-Principal": {url.QueryEscape("alice ü")},
		"X-Cpa-Tailnet-Login":     {"alice%40github"},
	}
	r := Authenticate(cfg, secret, ModeSystem, CanonicalHeader(ok))
	if !r.Authenticated || r.Principal != "alice ü" || r.Metadata["login"] != "alice@github" || r.Metadata["mode"] != ModeSystem {
		t.Fatalf("valid secret: %+v", r)
	}
	bad := map[string][]string{"X-Cpa-Tailnet-Secret": {strings.Repeat("b", 64)}, "X-Cpa-Tailnet-Principal": {"alice"}}
	if Authenticate(cfg, secret, ModeSystem, CanonicalHeader(bad)).Authenticated {
		t.Fatal("wrong secret authenticated")
	}
	// Tailscale-User-Login is ignored outside headers mode.
	serve := map[string][]string{"Tailscale-User-Login": {"alice@github"}}
	if Authenticate(cfg, secret, ModeSystem, CanonicalHeader(serve)).Authenticated {
		t.Fatal("serve header accepted in system mode")
	}
	hcfg := mustConfig(t, "mode: headers\nprincipal_map:\n  alice@github: alice\n")
	if r := Authenticate(hcfg, secret, ModeHeaders, CanonicalHeader(serve)); !r.Authenticated || r.Principal != "alice" {
		t.Fatalf("headers mode: %+v", r)
	}
	if Authenticate(hcfg, secret, ModeHeaders, CanonicalHeader(nil)).Authenticated {
		t.Fatal("headers mode without login")
	}
	// The secret alone is not enough in headers mode: no proxy runs there.
	if Authenticate(hcfg, secret, ModeHeaders, CanonicalHeader(ok)).Authenticated {
		t.Fatal("secret accepted in headers mode")
	}
}

type fakeWhois map[string]Identity

func (f fakeWhois) WhoIs(_ context.Context, addr string) (Identity, error) {
	host, _, _ := net.SplitHostPort(addr)
	id, ok := f[host]
	if !ok {
		return Identity{}, ErrPeerNotFound
	}
	return id, nil
}

func TestProxyStripsSpoofedHeadersAndInjectsIdentity(t *testing.T) {
	var got http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	cfg := mustConfig(t, "mode: system\nupstream: "+upstream.URL+"\nprincipal_map:\n  alice@github: alice\nallow_tagged:\n  tag:ci: ci\n")
	secret := strings.Repeat("s", 64)
	h := NewProxy(ProxyOptions{Config: cfg, Secret: secret, Self: selfFn("proxy.tail1.ts.net", "100.64.0.100"), Whois: fakeWhois{
		"100.64.0.1": {Login: "alice@github", Node: "laptop"},
		"100.64.0.2": {Tagged: true, Tags: []string{"tag:other"}},
	}})

	req := httptest.NewRequest("POST", "http://proxy/v1/chat/completions", strings.NewReader("{}"))
	req.RemoteAddr = "100.64.0.1:5555"
	for _, k := range []string{HeaderSecret, HeaderLogin, HeaderPrincipal, HeaderNode, "X-Cpa-Tailnet-Extra", "Tailscale-User-Login", "X-Real-IP"} {
		req.Header.Set(k, "evil")
	}
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("Authorization", "Bearer dummy")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	checks := map[string]string{
		HeaderSecret: secret, HeaderLogin: "alice%40github", HeaderPrincipal: "alice", HeaderNode: "laptop",
		"X-Forwarded-For": "100.64.0.1", "X-Real-Ip": "100.64.0.1", "Authorization": "Bearer dummy",
		"X-Cpa-Tailnet-Extra": "", "Tailscale-User-Login": "",
	}
	for k, want := range checks {
		if v := got.Values(k); strings.Join(v, ",") != want {
			t.Errorf("%s = %q, want %q", k, v, want)
		}
	}

	for addr, code := range map[string]int{"100.64.0.2:1": 403, "100.64.0.9:1": 403} {
		req := httptest.NewRequest("GET", "http://proxy/v1/models", nil)
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != code {
			t.Errorf("%s: status %d, want %d", addr, rec.Code, code)
		}
	}
}

func TestProxyStreamsAndUpgrades(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			hj, _ := w.(http.Hijacker)
			conn, brw, _ := hj.Hijack()
			defer conn.Close()
			_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			_ = brw.Flush()
			buf := make([]byte, 4)
			n, _ := io.ReadFull(brw, buf)
			_, _ = conn.Write(buf[:n])
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: 1\n\n")
		w.(http.Flusher).Flush()
	}))
	defer upstream.Close()
	cfg := mustConfig(t, "mode: system\nallow_self: true\nallowed_hosts: [x]\nrequire_mapping: false\nupstream: "+upstream.URL+"\n")
	h := NewProxy(ProxyOptions{Config: cfg, Secret: "x", Self: selfFn("n.ts.net", "127.0.0.1"), Whois: fakeWhois{"127.0.0.1": {Login: "a@b"}}})
	front := httptest.NewServer(h)
	defer front.Close()

	resp, err := http.Get(front.URL + "/v1/chat/completions")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "data: 1\n\n" {
		t.Fatalf("sse body %q", body)
	}

	conn, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(conn, "GET /v1/responses HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if !strings.Contains(string(buf[:n]), "101") {
		t.Fatalf("no 101: %q", buf[:n])
	}
	_, _ = io.WriteString(conn, "ping")
	echo := make([]byte, 4)
	if _, err := io.ReadFull(conn, echo); err != nil || string(echo) != "ping" {
		t.Fatalf("echo %q %v", echo, err)
	}
}

type fakeAPI struct {
	st  BackendStatus
	err error
}

func (f fakeAPI) StatusWithoutPeers(context.Context) (BackendStatus, error) { return f.st, f.err }

type fakeLn struct{ addr string }

func (l fakeLn) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (l fakeLn) Close() error              { return nil }
func (l fakeLn) Addr() net.Addr            { return &net.TCPAddr{} }

func TestSelectMode(t *testing.T) {
	running := BackendStatus{BackendState: "Running", DNSName: "mac.ts.net", TailscaleIPs: []netip.Addr{
		netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd7a::1"),
	}}
	bindAll := func(_, addr string) (net.Listener, error) { return fakeLn{addr}, nil }
	bindV4 := func(_, addr string) (net.Listener, error) {
		if strings.HasPrefix(addr, "[") {
			return nil, errors.New("no v6")
		}
		return fakeLn{addr}, nil
	}
	bindNone := func(_, addr string) (net.Listener, error) { return nil, errors.New("in use") }

	absent := &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	missing := &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", syscall.ENOENT)}
	cases := []struct {
		name, mode string
		api        LocalAPI
		bind       Binder
		want       string
		lns        int
		retry      bool
	}{
		{"auto running", ModeAuto, fakeAPI{st: running}, bindAll, ModeSystem, 2, false},
		{"auto v4 only", ModeAuto, fakeAPI{st: running}, bindV4, ModeSystem, 1, false},
		{"auto bind fails retries", ModeAuto, fakeAPI{st: running}, bindNone, "", 0, true},
		{"auto refused -> embedded", ModeAuto, fakeAPI{err: fmt.Errorf("wrapped: %w", absent)}, bindAll, ModeEmbedded, 0, false},
		{"auto no socket -> embedded", ModeAuto, fakeAPI{err: missing}, bindAll, ModeEmbedded, 0, false},
		{"auto timeout retries", ModeAuto, fakeAPI{err: context.DeadlineExceeded}, bindAll, "", 0, true},
		{"auto starting retries", ModeAuto, fakeAPI{st: BackendStatus{BackendState: "Starting"}}, bindAll, "", 0, true},
		{"auto needs login retries", ModeAuto, fakeAPI{st: BackendStatus{BackendState: "NeedsLogin"}}, bindAll, "", 0, true},
		{"auto no ips retries", ModeAuto, fakeAPI{st: BackendStatus{BackendState: "Running"}}, bindAll, "", 0, true},
		{"system ok", ModeSystem, fakeAPI{st: running}, bindAll, ModeSystem, 2, false},
		{"system absent retries", ModeSystem, fakeAPI{err: absent}, bindAll, "", 0, true},
		{"embedded", ModeEmbedded, fakeAPI{st: running}, bindAll, ModeEmbedded, 0, false},
		{"headers", ModeHeaders, fakeAPI{err: errors.New("x")}, bindAll, ModeHeaders, 0, false},
	}
	for _, c := range cases {
		cfg := mustConfig(t, "mode: "+c.mode+"\n")
		d, err := SelectMode(context.Background(), cfg, c.api, c.bind)
		var re *RetryError
		if errors.As(err, &re) != c.retry || (err != nil && !c.retry) || d.Mode != c.want || len(d.Listeners) != c.lns {
			t.Errorf("%s: got %q lns=%d err=%v", c.name, d.Mode, len(d.Listeners), err)
		}
		if d.Mode == ModeEmbedded && d.Reason == "" && c.mode == ModeAuto {
			t.Errorf("%s: auto fallback without a reason", c.name)
		}
	}
}

// fakeBackend is a system backend over real loopback listeners.
type fakeBackend struct {
	fakeAPI
	closed atomic.Int32
}

func (b *fakeBackend) Name() string { return "fake" }
func (b *fakeBackend) WhoIs(ctx context.Context, a string) (Identity, error) {
	return Identity{Login: "alice@github", Node: "n"}, nil
}
func (b *fakeBackend) Listen(int) ([]net.Listener, error) { return nil, errors.New("unused") }
func (b *fakeBackend) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return nil, errors.New("unused")
}
func (b *fakeBackend) Close() error { b.closed.Add(1); return nil }

func TestPluginLifecycle(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Header.Get(HeaderSecret))
	}))
	defer upstream.Close()
	be := &fakeBackend{fakeAPI: fakeAPI{st: BackendStatus{BackendState: "Running", DNSName: "mac.ts.net",
		TailscaleIPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}}}
	deps := Deps{
		NewSystem:   func(*Config) Backend { return be },
		NewEmbedded: func(*Config) (Backend, error) { return nil, errors.New("no embedded in tests") },
		Bind:        net.Listen,
	}
	p := NewPlugin(deps, testEnv(nil))
	port := freePort(t)
	reg := func(method, y string) map[string]any {
		req, _ := json.Marshal(map[string]any{"config_yaml": []byte(y), "schema_version": 6})
		var env struct {
			OK     bool
			Result map[string]any
			Error  map[string]any
		}
		if err := json.Unmarshal(p.Handle(method, req), &env); err != nil || !env.OK {
			t.Fatalf("%s: %v %v", method, err, env.Error)
		}
		return env.Result
	}
	res := reg("plugin.register", lcCfg(port, upstream.URL))
	if res["schema_version"].(float64) != 6 {
		t.Fatalf("schema: %v", res)
	}

	// Wait for the listener, then check the proxy passes the secret.
	var body string
	for i := 0; i < 50; i++ {
		resp, err := http.Get("http://127.0.0.1:" + itoa(port) + "/x")
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			body = string(b)
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(body) != 64 {
		t.Fatalf("proxy did not inject the secret: %q", body)
	}
	authReq, _ := json.Marshal(map[string]any{"Method": "GET", "Path": "/v1/models", "Headers": map[string][]string{
		"X-Cpa-Tailnet-Secret": {body}, "X-Cpa-Tailnet-Principal": {"alice%40github"},
	}, "Body": []byte("{}")})
	if out := string(p.Handle("frontend_auth.authenticate", authReq)); !strings.Contains(out, `"Authenticated":true`) {
		t.Fatalf("authenticate: %s", out)
	}

	// Management status never contains the secret.
	mreq, _ := json.Marshal(map[string]string{"Method": "GET", "Path": "/v0/management/tailscale-identity/status"})
	mout := p.Handle("management.handle", mreq)
	if strings.Contains(string(mout), body) {
		t.Fatal("status leaks the secret")
	}
	var menv struct{ Result mgmtResponse }
	_ = json.Unmarshal(mout, &menv)
	var rep StatusReport
	_ = json.Unmarshal(menv.Result.Body, &rep)
	if rep.Mode != ModeSystem || rep.DNSName != "mac.ts.net" || len(rep.Listen) != 1 {
		t.Fatalf("status: %+v", rep)
	}

	// Same config: no restart. Quiesce, reconfigure, shutdown twice.
	reg("plugin.reconfigure", lcCfg(port, upstream.URL))
	p.Handle("plugin.quiesce", []byte("{}"))
	if be.closed.Load() != 1 {
		t.Fatalf("quiesce did not close the backend: %d", be.closed.Load())
	}
	reg("plugin.reconfigure", lcCfg(port, upstream.URL))
	p.Shutdown()
	p.Shutdown()
	if _, err := net.DialTimeout("tcp", "127.0.0.1:"+itoa(port), 200*time.Millisecond); err == nil {
		t.Fatal("listener still open after shutdown")
	}
	if !strings.Contains(string(p.Handle("frontend_auth.authenticate", authReq)), `"Authenticated":false`) {
		t.Fatal("authenticated after shutdown")
	}
	// Init again in the same process.
	p.Reopen()
	reg("plugin.register", "enabled: true\nmode: headers\n")
	if !strings.Contains(string(p.Handle("nope", nil)), "unknown_method") {
		t.Fatal("unknown method")
	}
	p.Shutdown()
}

func lcCfg(port int, up string) string {
	return "enabled: true\nmode: auto\nallow_self: true\nprincipal_map: {alice@github: alice}\nlisten_port: " + itoa(port) + "\nupstream: " + up + "\n"
}

func selfFn(dns string, ips ...string) func() SelfInfo {
	var a []netip.Addr
	for _, ip := range ips {
		a = append(a, netip.MustParseAddr(ip))
	}
	return func() SelfInfo { return SelfInfo{IPs: a, DNSName: dns} }
}

func TestProxyRequestPolicy(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	cfg := mustConfig(t, "mode: system\nupstream: "+upstream.URL+"\nprincipal_map: {alice@github: alice}\nallowed_origins: [\"https://app.example/\"]\nallowed_hosts: [cpa.example]\n")
	whois := fakeWhois{
		"100.64.0.1":   {Login: "alice@github"},
		"100.64.0.100": {Login: "alice@github"}, // the node itself, owned by alice
		"100.64.0.3":   {Login: "mallory@github"},
	}
	h := NewProxy(ProxyOptions{Config: cfg, Secret: "s", Whois: whois, Self: selfFn("cliproxy.tail1.ts.net", "100.64.0.100", "fd7a::100")})
	do := func(method, target, host, remote string, hdr map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, nil)
		req.Host, req.RemoteAddr = host, remote
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	peer := "100.64.0.1:1234"
	cases := []struct {
		name, method, path, host, remote string
		hdr                              map[string]string
		code                             int
	}{
		{"short name", "GET", "/v1/models", "cliproxy:8318", peer, nil, 200},
		{"fqdn with dot", "GET", "/v1/models", "cliproxy.tail1.ts.net.:8318", peer, nil, 200},
		{"tailnet ip", "GET", "/v1/models", "100.64.0.100:8318", peer, nil, 200},
		{"tailnet ipv6", "GET", "/v1/models", "[fd7a::100]:8318", peer, nil, 200},
		{"allowed host", "GET", "/v1/models", "CPA.example", peer, nil, 200},
		{"rebinding host", "GET", "/v1/models", "evil.example:8318", peer, nil, 403},
		{"empty host", "GET", "/v1/models", "", peer, nil, 403},
		{"cross origin", "POST", "/v1/chat/completions", "cliproxy:8318", peer, map[string]string{"Origin": "https://attacker.example"}, 403},
		{"null origin", "POST", "/v1/chat/completions", "cliproxy:8318", peer, map[string]string{"Origin": "null"}, 403},
		{"preflight", "OPTIONS", "/v1/chat/completions", "cliproxy:8318", peer, map[string]string{"Origin": "https://attacker.example", "Access-Control-Request-Method": "POST"}, 403},
		{"bare options", "OPTIONS", "/v1/chat/completions", "cliproxy:8318", peer, nil, 403},
		{"sec-fetch cross-site", "GET", "/v1/models", "cliproxy:8318", peer, map[string]string{"Sec-Fetch-Site": "cross-site"}, 403},
		{"sec-fetch none", "GET", "/v1/models", "cliproxy:8318", peer, map[string]string{"Sec-Fetch-Site": "none"}, 200},
		{"allowed origin", "POST", "/v1/chat/completions", "cliproxy:8318", peer, map[string]string{"Origin": "https://app.example"}, 200},
		{"same origin", "POST", "/v1/chat/completions", "cliproxy:8318", peer, map[string]string{"Origin": "http://cliproxy:8318", "Sec-Fetch-Site": "same-origin"}, 200},
		{"sibling port origin", "POST", "/v1/chat/completions", "cliproxy:8318", peer, map[string]string{"Origin": "http://cliproxy:9999", "Sec-Fetch-Site": "same-site"}, 403},
		{"rebinding host", "POST", "/v1/chat/completions", "evil.example:8318", peer, map[string]string{"Origin": "http://evil.example:8318"}, 403},
		{"self ipv4", "GET", "/v1/models", "cliproxy:8318", "100.64.0.100:5000", nil, 403},
		{"self ipv6", "GET", "/v1/models", "cliproxy:8318", "[fd7a::100]:5000", nil, 403},
		{"unmapped login", "GET", "/v1/models", "cliproxy:8318", "100.64.0.3:1", nil, 403},
		{"management", "GET", "/v0/management/config", "cliproxy:8318", peer, nil, 403},
		{"management v8", "GET", "/v8/management/config", "cliproxy:8318", peer, nil, 403},
		{"management dot-dot", "GET", "/v1/../v0/management/config", "cliproxy:8318", peer, nil, 403},
		{"management double slash", "GET", "//v0//management/config", "cliproxy:8318", peer, nil, 403},
		{"management case", "GET", "/V0/Management/config", "cliproxy:8318", peer, nil, 403},
		{"control panel", "GET", "/management.html", "cliproxy:8318", peer, nil, 403},
		{"plugin resource", "GET", "/v0/resource/plugins/tailscale-identity/status", "cliproxy:8318", peer, nil, 403},
		{"oauth callback", "GET", "/codex/callback?code=x", "cliproxy:8318", peer, nil, 403},
		{"devin callback", "GET", "/callback?code=x", "cliproxy:8318", peer, nil, 403},
	}
	for _, c := range cases {
		hits.Store(0)
		rec := do(c.method, "http://x"+c.path, c.host, c.remote, c.hdr)
		if rec.Code != c.code {
			t.Errorf("%s: status %d, want %d (%s)", c.name, rec.Code, c.code, strings.TrimSpace(rec.Body.String()))
		}
		if c.code == 403 && hits.Load() != 0 {
			t.Errorf("%s: denied request reached the upstream", c.name)
		}
	}

	// CORS headers from the upstream never reach the client, except for an allowed origin.
	rec := do("GET", "http://x/v1/models", "cliproxy", peer, nil)
	for k := range rec.Header() {
		if strings.HasPrefix(k, "Access-Control-") {
			t.Errorf("upstream CORS header leaked: %s", k)
		}
	}
	rec = do("POST", "http://x/v1/models", "cliproxy", peer, map[string]string{"Origin": "https://app.example"})
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example" {
		t.Errorf("allowed origin ACAO = %q", got)
	}

	// Opt-ins.
	open := mustConfig(t, "mode: system\nupstream: "+upstream.URL+"\nprincipal_map: {alice@github: alice}\nallow_self: true\nforward_management: true\n")
	h = NewProxy(ProxyOptions{Config: open, Secret: "s", Whois: whois, Self: selfFn("cliproxy.tail1.ts.net", "100.64.0.100")})
	if rec := do("GET", "http://x/v0/management/config", "cliproxy", "100.64.0.100:1", nil); rec.Code != 200 {
		t.Errorf("opt-in self + management: %d", rec.Code)
	}
}

// stepAPI returns its statuses in order and repeats the last one.
type stepAPI struct {
	mu    sync.Mutex
	steps []fakeAPI
	calls int
}

func (s *stepAPI) StatusWithoutPeers(context.Context) (BackendStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := min(s.calls, len(s.steps)-1)
	s.calls++
	return s.steps[i].st, s.steps[i].err
}

type stepBackend struct {
	*stepAPI
	fakeBackend
}

func (b *stepBackend) StatusWithoutPeers(ctx context.Context) (BackendStatus, error) {
	return b.stepAPI.StatusWithoutPeers(ctx)
}

func TestRuntimeRetriesSystemMode(t *testing.T) {
	port := freePort(t)
	running := BackendStatus{BackendState: "Running", DNSName: "mac.ts.net", TailscaleIPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	api := &stepAPI{steps: []fakeAPI{
		{err: context.DeadlineExceeded},
		{st: BackendStatus{BackendState: "Starting"}},
		{st: running},
	}}
	var embedded atomic.Int32
	deps := Deps{
		NewSystem:   func(*Config) Backend { return &stepBackend{stepAPI: api} },
		NewEmbedded: func(*Config) (Backend, error) { embedded.Add(1); return nil, errors.New("must not start") },
		Bind:        net.Listen,
		RetryMin:    5 * time.Millisecond,
		RetryMax:    20 * time.Millisecond,
	}
	cfg := mustConfig(t, "mode: auto\nlisten_port: "+itoa(port)+"\n")
	rt := StartRuntime(cfg, "s", deps)
	defer rt.Stop(2 * time.Second)
	deadline := time.Now().Add(3 * time.Second)
	for rt.Mode() != ModeSystem && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if rt.Mode() != ModeSystem || len(rt.Listen()) != 1 || embedded.Load() != 0 || rt.Failed() {
		t.Fatalf("mode=%s listen=%v embedded=%d failed=%v", rt.Mode(), rt.Listen(), embedded.Load(), rt.Failed())
	}
}

func TestRegisterRestartsFailedRuntime(t *testing.T) {
	var calls atomic.Int32
	deps := Deps{
		NewSystem:   func(*Config) Backend { return &fakeBackend{} },
		NewEmbedded: func(*Config) (Backend, error) { calls.Add(1); return nil, errors.New("boom") },
		Bind:        net.Listen,
	}
	p := NewPlugin(deps, testEnv(nil))
	defer p.Shutdown()
	req, _ := json.Marshal(map[string]any{"config_yaml": []byte("mode: embedded\n"), "schema_version": 6})
	wait := func(n int32) {
		for i := 0; i < 100 && calls.Load() < n; i++ {
			time.Sleep(10 * time.Millisecond)
		}
		p.mu.RLock()
		rt := p.rt
		p.mu.RUnlock()
		for i := 0; i < 100 && !rt.Failed(); i++ {
			time.Sleep(10 * time.Millisecond)
		}
	}
	p.Handle("plugin.register", req)
	wait(1)
	p.Handle("plugin.reconfigure", req)
	wait(2)
	if calls.Load() != 2 {
		t.Fatalf("same config after a failed start did not restart: %d starts", calls.Load())
	}
}

func TestSameAddrs(t *testing.T) {
	a, b := netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd7a::1")
	if !sameAddrs([]netip.Addr{a, b}, []netip.Addr{b, a}) || sameAddrs([]netip.Addr{a}, []netip.Addr{a, b}) || sameAddrs([]netip.Addr{a}, []netip.Addr{b}) {
		t.Fatal("sameAddrs")
	}
}

func freePort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestMaskPrincipal(t *testing.T) {
	if got := maskPrincipal("alice"); got != "alice" {
		t.Fatalf("short principal changed: %q", got)
	}
	if got := maskPrincipal("sk-test-AAAAAAAAAAAAAAAAAAAAAA"); got != "sk-tes...AAAA" {
		t.Fatalf("long principal not masked: %q", got)
	}
}
