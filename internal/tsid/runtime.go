package tsid

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// Deps are the side-effecting constructors. Tests replace them.
type Deps struct {
	NewSystem   func(cfg *Config) Backend
	NewEmbedded func(cfg *Config) (Backend, error)
	Bind        Binder
	// RetryMin and RetryMax bound the backoff while system mode waits for
	// tailscaled. Defaults: 1s and 30s.
	RetryMin, RetryMax time.Duration
}

// DefaultDeps uses the real tailscaled LocalAPI, tsnet and net.Listen.
func DefaultDeps() Deps {
	return Deps{
		NewSystem:   func(cfg *Config) Backend { return newSystemBackend(cfg) },
		NewEmbedded: newEmbeddedBackend,
		Bind:        net.Listen,
	}
}

func (d Deps) retryBounds() (time.Duration, time.Duration) {
	lo, hi := d.RetryMin, d.RetryMax
	if lo <= 0 {
		lo = time.Second
	}
	if hi < lo {
		hi = 30 * time.Second
		if hi < lo {
			hi = lo
		}
	}
	return lo, hi
}

// Runtime is one started configuration: backend, listeners and servers.
type Runtime struct {
	cfg    *Config
	secret string
	deps   Deps

	startCtx    context.Context
	cancelStart context.CancelFunc
	reqCtx      context.Context
	cancelReq   context.CancelFunc
	wg          sync.WaitGroup

	mu      sync.Mutex
	mode    string
	reason  string
	backend Backend
	sys     Backend // system LocalAPI client, set before mode selection
	servers []*http.Server
	listen  []string
	status  BackendStatus
	lastErr string
	authURL string
	stopped bool
	failed  bool
}

// StartRuntime starts the runtime in the background and returns at once.
func StartRuntime(cfg *Config, secret string, deps Deps) *Runtime {
	r := &Runtime{cfg: cfg, secret: secret, deps: deps, mode: "starting"}
	r.startCtx, r.cancelStart = context.WithCancel(context.Background())
	r.reqCtx, r.cancelReq = context.WithCancel(context.Background())
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		if err := r.run(); err != nil && r.startCtx.Err() == nil {
			r.mu.Lock()
			r.failed = true
			r.lastErr = err.Error()
			r.mu.Unlock()
			Logf("error", "tailscale-identity: start failed", map[string]any{"error": err.Error(), "mode": cfg.Mode})
		}
	}()
	return r
}

// Failed reports whether the runtime gave up. A register call with the same
// config then starts a new runtime.
func (r *Runtime) Failed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.failed
}

func (r *Runtime) sleep(d time.Duration) bool {
	select {
	case <-r.startCtx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// run selects the mode, serves, and in system mode selects again when the
// tailnet IPs change or a listener fails. It retries system mode with a
// capped backoff until it succeeds or Stop cancels it.
func (r *Runtime) run() error {
	cfg := r.cfg
	var sys Backend
	if cfg.Mode == ModeAuto || cfg.Mode == ModeSystem {
		sys = r.deps.NewSystem(cfg)
		r.mu.Lock()
		r.sys = sys
		r.mu.Unlock()
	}
	lo, hi := r.deps.retryBounds()
	backoff, lastReason := lo, ""
	for {
		if r.startCtx.Err() != nil {
			return nil
		}
		dec, err := SelectMode(r.startCtx, cfg, apiOrNil(sys), r.deps.Bind)
		var re *RetryError
		if errors.As(err, &re) {
			r.mu.Lock()
			r.mode, r.reason, r.lastErr = "waiting", re.Reason, re.Error()
			if re.Status.BackendState != "" {
				r.status = re.Status
			}
			r.mu.Unlock()
			if re.Reason != lastReason {
				Logf("warn", "tailscale-identity: waiting for tailscaled", map[string]any{"reason": re.Reason, "configured": cfg.Mode})
				lastReason = re.Reason
			}
			if !r.sleep(backoff) {
				return nil
			}
			backoff = min(backoff*2, hi)
			continue
		}
		if err != nil {
			return err
		}
		backoff, lastReason = lo, ""
		again, err := r.serve(dec, sys)
		if err != nil || !again {
			return err
		}
	}
}

// serve starts the listeners of one decision and blocks in the monitor.
// It returns true when system mode must select and bind again.
func (r *Runtime) serve(dec Decision, sys Backend) (bool, error) {
	cfg := r.cfg
	r.mu.Lock()
	r.mode, r.reason, r.status, r.lastErr = dec.Mode, dec.Reason, dec.Status, ""
	r.mu.Unlock()
	Logf("info", "tailscale-identity: mode selected", map[string]any{
		"configured": cfg.Mode, "mode": dec.Mode, "reason": dec.Reason,
		"node": dec.Status.DNSName, "tailnet_ips": addrStrings(dec.Status.TailscaleIPs),
	})

	var lns []net.Listener
	var be Backend
	var err error
	switch dec.Mode {
	case ModeHeaders:
		return false, nil
	case ModeSystem:
		be, lns = sys, dec.Listeners
	case ModeEmbedded:
		if r.startCtx.Err() != nil {
			return false, nil
		}
		be, err = r.deps.NewEmbedded(cfg)
		if err != nil {
			return false, fmt.Errorf("embedded: %w", err)
		}
		lns, err = be.Listen(cfg.ListenPort)
		if err != nil {
			_ = be.Close()
			return false, fmt.Errorf("embedded listen: %w", err)
		}
	}

	serveErr := make(chan error, len(lns))
	r.mu.Lock()
	if r.stopped || r.startCtx.Err() != nil {
		r.mu.Unlock()
		for _, ln := range lns {
			_ = ln.Close()
		}
		if be != nil && dec.Mode == ModeEmbedded {
			_ = be.Close()
		}
		return false, nil
	}
	r.backend = be
	handler := NewProxy(ProxyOptions{Config: cfg, Whois: be, Self: r.selfInfo, Secret: r.secret, TLS: cfg.TLS, Logf: Logf})
	for _, ln := range lns {
		addr := ln.Addr().String()
		if cfg.TLS {
			ln = tls.NewListener(ln, &tls.Config{
				GetCertificate: be.GetCertificate,
				NextProtos:     []string{"h2", "http/1.1"},
				MinVersion:     tls.VersionTLS12,
			})
		}
		srv := &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 30 * time.Second,
			IdleTimeout:       120 * time.Second,
			BaseContext:       func(net.Listener) context.Context { return r.reqCtx },
		}
		r.servers = append(r.servers, srv)
		r.listen = append(r.listen, addr)
		r.wg.Add(1)
		go func(srv *http.Server, ln net.Listener) {
			defer r.wg.Done()
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				r.setErr(err)
				serveErr <- err
			}
		}(srv, ln)
	}
	r.mu.Unlock()
	Logf("info", "tailscale-identity: listening", map[string]any{"listen": r.Listen(), "upstream": cfg.Upstream, "tls": cfg.TLS})
	if cfg.ForwardManagement {
		Logf("warn", "tailscale-identity: forward_management is on. Set server.trusted-proxies to [\"127.0.0.1\", \"::1\"] in CLIProxyAPI, or every tailnet caller looks local to management", nil)
	}

	again := r.monitor(be, dec.Mode, dec.Status.TailscaleIPs, serveErr)
	if again {
		r.closeServers()
	}
	return again, nil
}

// closeServers stops the current listeners before system mode binds again.
func (r *Runtime) closeServers() {
	r.mu.Lock()
	servers := r.servers
	r.servers, r.listen = nil, nil
	r.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(ctx)
		_ = s.Close()
	}
}

// selfInfo returns the node's own names and IPs for the proxy checks.
func (r *Runtime) selfInfo() SelfInfo {
	r.mu.Lock()
	st, be := r.status, r.backend
	r.mu.Unlock()
	if len(st.TailscaleIPs) == 0 && be != nil {
		ctx, cancel := context.WithTimeout(r.reqCtx, 2*time.Second)
		if fresh, err := be.StatusWithoutPeers(ctx); err == nil {
			st = fresh
			r.mu.Lock()
			r.status = fresh
			r.mu.Unlock()
		}
		cancel()
	}
	return SelfInfo{IPs: st.TailscaleIPs, HostName: st.HostName, DNSName: st.DNSName}
}

func sameAddrs(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[netip.Addr]bool, len(a))
	for _, x := range a {
		set[x] = true
	}
	for _, x := range b {
		if !set[x] {
			return false
		}
	}
	return true
}

// monitor refreshes the cached status and logs login URLs and state changes.
// In system mode it returns true when the tailnet IPs change or a listener
// fails, so the caller binds again.
func (r *Runtime) monitor(be Backend, mode string, bound []netip.Addr, serveErr <-chan error) bool {
	lastState := ""
	for {
		ctx, cancel := context.WithTimeout(r.startCtx, 5*time.Second)
		st, err := be.StatusWithoutPeers(ctx)
		cancel()
		interval := 30 * time.Second
		if err == nil {
			r.mu.Lock()
			r.status = st
			newURL := st.AuthURL != "" && st.AuthURL != r.authURL
			r.authURL = st.AuthURL
			r.mu.Unlock()
			if newURL {
				Logf("warn", "tailscale-identity: login required, open this URL to add the node to your tailnet", map[string]any{"auth_url": st.AuthURL})
			}
			if st.BackendState != lastState {
				Logf("info", "tailscale-identity: backend state", map[string]any{"state": st.BackendState, "node": st.DNSName, "tailnet_ips": addrStrings(st.TailscaleIPs)})
				lastState = st.BackendState
			}
			if st.BackendState != "Running" {
				interval = 3 * time.Second
			} else if mode == ModeSystem && !sameAddrs(st.TailscaleIPs, bound) {
				Logf("warn", "tailscale-identity: tailnet IPs changed, binding again", map[string]any{
					"old": addrStrings(bound), "new": addrStrings(st.TailscaleIPs)})
				return true
			}
		} else if r.startCtx.Err() == nil {
			r.setErr(fmt.Errorf("status: %w", err))
			interval = 5 * time.Second
		}
		select {
		case <-r.startCtx.Done():
			return false
		case err := <-serveErr:
			if mode == ModeSystem {
				Logf("warn", "tailscale-identity: listener failed, binding again", map[string]any{"error": err.Error()})
				return true
			}
		case <-time.After(interval):
		}
	}
}

// Stop closes servers, listeners and the backend. It is idempotent and
// bounded by timeout.
func (r *Runtime) Stop(timeout time.Duration) {
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return
	}
	r.stopped = true
	r.mu.Unlock()

	r.cancelStart()
	deadline := time.Now().Add(timeout)

	r.mu.Lock()
	servers := append([]*http.Server(nil), r.servers...)
	be := r.backend
	r.mu.Unlock()

	graceCtx, cancel := context.WithTimeout(context.Background(), timeout/3)
	for _, s := range servers {
		_ = s.Shutdown(graceCtx)
	}
	cancel()
	r.cancelReq() // ends streams and hijacked WebSocket conns
	for _, s := range servers {
		_ = s.Close()
	}
	if be != nil {
		done := make(chan struct{})
		go func() { _ = be.Close(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Until(deadline)):
			Logf("warn", "tailscale-identity: backend close timed out", nil)
		}
	}
	waited := make(chan struct{})
	go func() { r.wg.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(time.Until(deadline)):
		Logf("warn", "tailscale-identity: background goroutines still running after stop", nil)
	}
}

// Mode returns the active mode ("starting" until selection ends).
func (r *Runtime) Mode() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.mode
}

// Listen returns the bound addresses.
func (r *Runtime) Listen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.listen...)
}

func (r *Runtime) setErr(err error) {
	r.mu.Lock()
	r.lastErr = err.Error()
	r.mu.Unlock()
}

// StatusReport is the management status payload. It never holds the secret.
type StatusReport struct {
	Mode           string   `json:"mode"`
	ConfiguredMode string   `json:"configured_mode"`
	ModeReason     string   `json:"mode_reason,omitempty"`
	BackendState   string   `json:"backend_state"`
	Node           string   `json:"node"`
	TailnetIPs     []string `json:"tailnet_ips"`
	DNSName        string   `json:"dns_name"`
	AuthURL        string   `json:"auth_url"`
	Listen         []string `json:"listen"`
	TLS            bool     `json:"tls"`
	Upstream       string   `json:"upstream"`
	LastError      string   `json:"last_error"`
}

// Report builds a status report. It refreshes the backend status with a
// short timeout and falls back to the cached value.
func (r *Runtime) Report(ctx context.Context) StatusReport {
	r.mu.Lock()
	be := r.backend
	r.mu.Unlock()
	if be != nil {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		if st, err := be.StatusWithoutPeers(cctx); err == nil {
			r.mu.Lock()
			r.status = st
			r.authURL = st.AuthURL
			r.mu.Unlock()
		}
		cancel()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.status
	rep := StatusReport{
		Mode: r.mode, ConfiguredMode: r.cfg.Mode, ModeReason: r.reason,
		BackendState: st.BackendState, Node: st.HostName, TailnetIPs: addrStrings(st.TailscaleIPs),
		DNSName: st.DNSName, AuthURL: st.AuthURL, Listen: append([]string{}, r.listen...),
		TLS: r.cfg.TLS, Upstream: r.cfg.Upstream, LastError: r.lastErr,
	}
	if rep.Mode == ModeHeaders {
		rep.BackendState = "n/a"
	}
	if rep.TailnetIPs == nil {
		rep.TailnetIPs = []string{}
	}
	return rep
}

func apiOrNil(b Backend) LocalAPI {
	if b == nil {
		return nilAPI{}
	}
	return b
}

type nilAPI struct{}

func (nilAPI) StatusWithoutPeers(context.Context) (BackendStatus, error) {
	return BackendStatus{}, errNoLocalAPI
}

func addrStrings[T fmt.Stringer](v []T) []string {
	out := make([]string, 0, len(v))
	for _, a := range v {
		out = append(out, a.String())
	}
	return out
}
