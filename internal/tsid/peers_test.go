package tsid

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

func testStatus(state string) *ipnstate.Status {
	tags := views.SliceOf([]string{"tag:ci"})
	return &ipnstate.Status{
		BackendState: state,
		Self:         &ipnstate.PeerStatus{HostName: "mac", DNSName: "mac.tail1.ts.net.", UserID: 1, Online: true},
		User: map[tailcfg.UserID]tailcfg.UserProfile{
			1: {LoginName: "owner@github", DisplayName: "Owner"},
			2: {LoginName: "Bob@example.com", DisplayName: "Bob"},
			3: {LoginName: "tagged-devices", DisplayName: "Tagged Devices"},
			4: {LoginName: "carol@other", DisplayName: "Carol"},
		},
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			key.NewNode().Public(): {HostName: "phone", DNSName: "phone.tail1.ts.net.", UserID: 1, Online: false, OS: "iOS"},
			key.NewNode().Public(): {HostName: "laptop", DNSName: "laptop.tail1.ts.net.", UserID: 2, Online: true},
			key.NewNode().Public(): {HostName: "ci", DNSName: "ci.tail1.ts.net.", UserID: 3, Tags: &tags, Online: true},
			key.NewNode().Public(): {HostName: "carol-pc", DNSName: "carol-pc.other.ts.net.", UserID: 4, ShareeNode: true},
			key.NewNode().Public(): nil,
		},
	}
}

func TestPeersFromIPN(t *testing.T) {
	rep := peersFromIPN(testStatus("Running"))
	if rep.BackendState != "Running" || rep.Reason != "" {
		t.Fatalf("state/reason: %+v", rep)
	}
	if rep.OwnerLogin != "owner@github" || rep.OwnerDisplayName != "Owner" {
		t.Fatalf("owner: %q %q", rep.OwnerLogin, rep.OwnerDisplayName)
	}
	if rep.Self == nil || rep.Self.Node != "mac" || rep.Self.DNSName != "mac.tail1.ts.net" || rep.Self.Login != "owner@github" {
		t.Fatalf("self: %+v", rep.Self)
	}
	var got []string
	for _, p := range rep.Peers {
		got = append(got, p.Login+"/"+p.Node)
	}
	// Sorted by login (case-insensitive), tagged nodes last.
	want := "Bob@example.com/laptop carol@other/carol-pc owner@github/phone /ci"
	if strings.Join(got, " ") != want {
		t.Fatalf("order: %q", strings.Join(got, " "))
	}
	ci := rep.Peers[3]
	if !ci.Tagged || ci.Login != "" || ci.DisplayName != "" || len(ci.Tags) != 1 || ci.Tags[0] != "tag:ci" {
		t.Fatalf("tagged peer: %+v", ci)
	}
	if !rep.Peers[1].Shared || rep.Peers[1].Online {
		t.Fatalf("shared peer: %+v", rep.Peers[1])
	}
	if rep.Peers[2].OS != "iOS" || rep.Peers[2].DisplayName != "Owner" || rep.Peers[0].Tags == nil {
		t.Fatalf("peer fields: %+v %+v", rep.Peers[2], rep.Peers[0])
	}
	// JSON: tags is [] (not null), and the field names are stable.
	b, _ := json.Marshal(rep)
	for _, s := range []string{`"owner_login":"owner@github"`, `"tags":[]`, `"shared":true`, `"tagged":true`, `"dns_name":"laptop.tail1.ts.net"`} {
		if !strings.Contains(string(b), s) {
			t.Fatalf("json lacks %s: %s", s, b)
		}
	}
}

func TestPeersFromIPNNotRunning(t *testing.T) {
	rep := peersFromIPN(testStatus("NeedsLogin"))
	if len(rep.Peers) != 0 || rep.Peers == nil || !strings.Contains(rep.Reason, "NeedsLogin") {
		t.Fatalf("not running: %+v", rep)
	}
	empty := peersFromIPN(&ipnstate.Status{BackendState: "Running"})
	if len(empty.Peers) != 0 || empty.Reason == "" || empty.Self != nil {
		t.Fatalf("no peers: %+v", empty)
	}
}

// peerBackend is a fakeBackend that also lists peers.
type peerBackend struct {
	fakeBackend
	rep PeersReport
	err error
}

func (b *peerBackend) Peers(context.Context) (PeersReport, error) { return b.rep, b.err }

func mgmtCall(t *testing.T, p *Plugin, method, path string) mgmtResponse {
	t.Helper()
	req, _ := json.Marshal(map[string]string{"Method": method, "Path": path})
	var env struct {
		OK     bool
		Result mgmtResponse
		Error  map[string]any
	}
	if err := json.Unmarshal(p.Handle("management.handle", req), &env); err != nil || !env.OK {
		t.Fatalf("management.handle: %v %v", err, env.Error)
	}
	return env.Result
}

func peersCall(t *testing.T, p *Plugin) PeersReport {
	t.Helper()
	res := mgmtCall(t, p, "GET", "/v0/management/tailscale-identity/peers")
	if res.StatusCode != 200 || res.Headers["Content-Type"][0] != "application/json" || res.Headers["Cache-Control"][0] != "no-store" {
		t.Fatalf("peers response: %d %v", res.StatusCode, res.Headers)
	}
	var rep PeersReport
	if err := json.Unmarshal(res.Body, &rep); err != nil {
		t.Fatalf("peers body: %v", err)
	}
	if rep.Peers == nil {
		t.Fatal("peers is null")
	}
	return rep
}

func registerYAML(t *testing.T, p *Plugin, y string) {
	t.Helper()
	req, _ := json.Marshal(map[string]any{"config_yaml": []byte(y), "schema_version": 6})
	if out := string(p.Handle("plugin.register", req)); !strings.Contains(out, `"ok":true`) {
		t.Fatalf("register: %s", out)
	}
}

func TestManagementRegisterListsPeersRoute(t *testing.T) {
	p := NewPlugin(Deps{}, testEnv(nil))
	out := string(p.Handle("management.register", []byte(`{"BasePath":"/v0/management","ResourceBasePath":"/v0/resource/plugins/tailscale-identity"}`)))
	for _, s := range []string{`"Path":"/tailscale-identity/status"`, `"Path":"/tailscale-identity/peers"`, `"Path":"/status"`} {
		if !strings.Contains(out, s) {
			t.Fatalf("register lacks %s: %s", s, out)
		}
	}
}

func TestManagementPeersRoute(t *testing.T) {
	be := &peerBackend{
		fakeBackend: fakeBackend{fakeAPI: fakeAPI{st: BackendStatus{BackendState: "Running", DNSName: "mac.ts.net",
			TailscaleIPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}}},
		rep: PeersReport{BackendState: "Running", OwnerLogin: "owner@github", Peers: []PeerInfo{{Login: "bob@example.com", Node: "laptop", Tags: []string{}}}},
	}
	p := NewPlugin(Deps{
		NewSystem:   func(*Config) Backend { return be },
		NewEmbedded: func(*Config) (Backend, error) { return nil, errors.New("no embedded in tests") },
		Bind:        net.Listen,
	}, testEnv(nil))
	defer p.Shutdown()

	// No config yet: stopped, empty list with a reason.
	if rep := peersCall(t, p); rep.Reason != "the plugin is stopped" || len(rep.Peers) != 0 {
		t.Fatalf("stopped: %+v", rep)
	}

	registerYAML(t, p, "mode: system\nlisten_port: "+itoa(freePort(t))+"\n")
	var rep PeersReport
	for i := 0; i < 100; i++ {
		if rep = peersCall(t, p); len(rep.Peers) == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(rep.Peers) != 1 || rep.Peers[0].Login != "bob@example.com" || rep.OwnerLogin != "owner@github" {
		t.Fatalf("peers: %+v", rep)
	}

	// A LocalAPI error gives an empty list with the reason.
	be.err = errors.New("socket gone")
	if rep := peersCall(t, p); len(rep.Peers) != 0 || !strings.Contains(rep.Reason, "socket gone") {
		t.Fatalf("error: %+v", rep)
	}
	be.err = nil

	// Headers mode asks the system tailscaled.
	registerYAML(t, p, "mode: headers\n")
	if rep := peersCall(t, p); len(rep.Peers) != 1 {
		t.Fatalf("headers: %+v", rep)
	}

	// Only GET is routed; other methods get 405.
	if res := mgmtCall(t, p, "POST", "/v0/management/tailscale-identity/peers"); res.StatusCode != 405 {
		t.Fatalf("POST: %d", res.StatusCode)
	}
}

func TestPeersWhileWaiting(t *testing.T) {
	// tailscaled answers but is not Running: the runtime waits, and the
	// peers route still reads the system LocalAPI.
	be := &peerBackend{
		fakeBackend: fakeBackend{fakeAPI: fakeAPI{st: BackendStatus{BackendState: "NeedsLogin"}}},
		rep:         PeersReport{BackendState: "NeedsLogin", Reason: "tailnet backend state is NeedsLogin", Peers: []PeerInfo{}},
	}
	p := NewPlugin(Deps{
		NewSystem: func(*Config) Backend { return be },
		Bind:      net.Listen,
		RetryMin:  10 * time.Millisecond, RetryMax: 20 * time.Millisecond,
	}, testEnv(nil))
	defer p.Shutdown()
	registerYAML(t, p, "mode: system\n")
	var rep PeersReport
	for i := 0; i < 100; i++ {
		if rep = peersCall(t, p); rep.BackendState == "NeedsLogin" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if rep.BackendState != "NeedsLogin" || !strings.Contains(rep.Reason, "NeedsLogin") {
		t.Fatalf("waiting: %+v", rep)
	}
}

func TestRuntimePeerSourceWithoutBackend(t *testing.T) {
	r := &Runtime{mode: "starting", reason: "x"}
	if src, reason := r.peerSource(); src != nil || !strings.Contains(reason, "mode starting: x") {
		t.Fatalf("peerSource: %v %q", src, reason)
	}
	// A backend without PeerLister gives a reason too.
	r.backend = &fakeBackend{}
	if src, _ := r.peerSource(); src != nil {
		t.Fatal("fakeBackend is not a PeerLister")
	}
}

func TestStatusPageShell(t *testing.T) {
	p := NewPlugin(Deps{}, testEnv(nil))
	_, _ = p.managementRegister([]byte(`{"ResourceBasePath":"/v0/resource/plugins/tailscale-identity"}`))
	res := mgmtCall(t, p, "GET", "/v0/resource/plugins/tailscale-identity/status")
	csp := strings.Join(res.Headers["Content-Security-Policy"], "")
	for _, s := range []string{"default-src 'none'", "connect-src 'self'", "frame-ancestors 'self'"} {
		if !strings.Contains(csp, s) {
			t.Fatalf("CSP lacks %s: %s", s, csp)
		}
	}
	body := string(res.Body)
	// The page holds no data and loads no external asset.
	for _, bad := range []string{"<link", "src=\"http", "href=\"http", "@import", "url(", "console.log"} {
		if strings.Contains(body, bad) {
			t.Fatalf("page contains %q", bad)
		}
	}
	for _, s := range []string{"/v0/management/\" + PLUGIN + \"/peers", "/v8/management/config/plugins/configs/", "cli-proxy-auth", "enc::v1::"} {
		if !strings.Contains(body, s) {
			t.Fatalf("page lacks %q", s)
		}
	}
}
