package tsid

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"
)

// Headers the proxy sets for CLIProxyAPI. Inbound copies are always removed.
const (
	HeaderLogin     = "X-CPA-Tailnet-Login"
	HeaderNode      = "X-CPA-Tailnet-Node"
	HeaderPrincipal = "X-CPA-Tailnet-Principal"
	HeaderSecret    = "X-CPA-Tailnet-Secret"

	// HeaderServeLogin is set by `tailscale serve` (headers mode).
	HeaderServeLogin = "Tailscale-User-Login"
)

// spoofable lists inbound headers that a tailnet client must not control.
var spoofable = []string{
	HeaderLogin, HeaderNode, HeaderPrincipal, HeaderSecret,
	"Tailscale-User-Login", "Tailscale-User-Name", "Tailscale-User-Profile-Pic",
	"Tailscale-App-Capabilities", "Tailscale-Headers-Info",
	"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-Ip", "Forwarded",
}

// StripSpoofable removes every identity and forwarding header.
// It also removes any header with the X-CPA-Tailnet- prefix.
func StripSpoofable(h http.Header) {
	for _, k := range spoofable {
		h.Del(k)
	}
	for k := range h {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), "X-Cpa-Tailnet-") {
			delete(h, k)
		}
	}
}

// Whoiser resolves a remote address to a tailnet identity.
type Whoiser interface {
	WhoIs(ctx context.Context, remoteAddr string) (Identity, error)
}

type identityKey struct{}

type requestIdentity struct {
	Identity
	Principal string
	IP        string
}

// SelfInfo describes the node the proxy listens on.
type SelfInfo struct {
	IPs      []netip.Addr
	HostName string
	DNSName  string // FQDN without the trailing dot
}

// ProxyOptions configures NewProxy.
type ProxyOptions struct {
	Config  *Config
	Whois   Whoiser
	Self    func() SelfInfo // the node's own names and IPs, for the Host and self checks
	Secret  string
	TLS     bool
	Logf    func(level, msg string, fields map[string]any)
	Timeout time.Duration // WhoIs timeout
}

// blockedPrefixes are management, resource and OAuth callback paths of
// CLIProxyAPI. The proxy does not forward them unless forward_management is
// set: proxied callers can look local to CLIProxyAPI.
var blockedPrefixes = []string{
	"/v0/management", "/v8/management", "/v0/resource", "/management.html",
	"/anthropic/callback", "/codex/callback", "/antigravity/callback", "/devin/callback",
}

// IsManagementPath reports whether p is a path the proxy blocks by default.
func IsManagementPath(p string) bool {
	c := strings.ToLower(path.Clean("/" + p))
	if c == "/callback" || strings.HasPrefix(c, "/callback/") {
		return true
	}
	for _, pre := range blockedPrefixes {
		if strings.HasPrefix(c, pre) {
			return true
		}
	}
	return false
}

func normalizeHost(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

// hostAllowed accepts the node's tailnet IPs, its MagicDNS short name, its
// FQDN, its host name and allowed_hosts. Other names (DNS rebinding) are rejected.
func hostAllowed(host string, self SelfInfo, extra []string) bool {
	h := normalizeHost(host)
	if h == "" {
		return false
	}
	if a, err := netip.ParseAddr(h); err == nil {
		a = a.Unmap()
		for _, ip := range self.IPs {
			if ip.Unmap() == a {
				return true
			}
		}
		return false
	}
	if fq := strings.ToLower(self.DNSName); fq != "" {
		if h == fq {
			return true
		}
		if short, _, _ := strings.Cut(fq, "."); h == short {
			return true
		}
	}
	if hn := strings.ToLower(self.HostName); hn != "" && h == hn {
		return true
	}
	for _, e := range extra {
		if h == e {
			return true
		}
	}
	return false
}

func isSelfIP(ip string, self SelfInfo) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, s := range self.IPs {
		if s.Unmap() == a {
			return true
		}
	}
	return false
}

func originAllowed(origin string, allowed []string) bool {
	o := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(origin)), "/")
	for _, a := range allowed {
		if o == a {
			return true
		}
	}
	return false
}

// NewProxy returns the tailnet-facing handler: request policy, WhoIs, allow
// or 403, then a streaming reverse proxy to the upstream.
func NewProxy(o ProxyOptions) http.Handler {
	upstream := o.Config.UpstreamURL()
	if o.Timeout == 0 {
		o.Timeout = 5 * time.Second
	}
	if o.Self == nil {
		o.Self = func() SelfInfo { return SelfInfo{} }
	}
	logf := o.Logf
	if logf == nil {
		logf = func(string, string, map[string]any) {}
	}
	cfg := o.Config
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	rp := &httputil.ReverseProxy{
		FlushInterval: -1,
		Transport:     transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			ri, _ := pr.In.Context().Value(identityKey{}).(*requestIdentity)
			pr.SetURL(upstream)
			StripSpoofable(pr.Out.Header)
			if ri == nil {
				return
			}
			proto := "http"
			if o.TLS {
				proto = "https"
			}
			pr.Out.Header.Set("X-Forwarded-For", ri.IP)
			pr.Out.Header.Set("X-Real-Ip", ri.IP)
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
			pr.Out.Header.Set("X-Forwarded-Proto", proto)
			pr.Out.Header.Set(HeaderLogin, url.QueryEscape(ri.Login))
			pr.Out.Header.Set(HeaderNode, url.QueryEscape(ri.Node))
			pr.Out.Header.Set(HeaderPrincipal, url.QueryEscape(ri.Principal))
			pr.Out.Header.Set(HeaderSecret, o.Secret)
		},
		// CLIProxyAPI answers every request with Access-Control-Allow-Origin: *.
		// Remove that, and allow only configured origins.
		ModifyResponse: func(resp *http.Response) error {
			for k := range resp.Header {
				if strings.HasPrefix(k, "Access-Control-") {
					delete(resp.Header, k)
				}
			}
			if resp.Request != nil {
				if origin := resp.Request.Header.Get("Origin"); origin != "" && originAllowed(origin, cfg.AllowedOrigins) {
					resp.Header.Set("Access-Control-Allow-Origin", origin)
					resp.Header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
					resp.Header.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
					resp.Header.Add("Vary", "Origin")
				}
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if !errors.Is(err, context.Canceled) {
				logf("warn", "tailscale-identity: upstream request failed", map[string]any{"error": err.Error(), "path": r.URL.Path})
			}
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			ip = host
		}
		deny := func(reason string) {
			if cfg.LogRequests {
				logf("info", "tailscale-identity: request denied", map[string]any{"reason": reason, "remote": ip, "method": r.Method, "path": r.URL.Path})
			}
			http.Error(w, "forbidden: "+reason, http.StatusForbidden)
		}
		// Browser checks first: the caller's tailnet identity is ambient
		// authority, so a web page in the caller's browser must not use it.
		// The Host check runs first, so a same-origin page is a page served
		// by this listener under a node name (no DNS rebinding).
		self := o.Self()
		if !hostAllowed(r.Host, self, cfg.AllowedHosts) {
			deny("host not allowed")
			return
		}
		scheme := "http"
		if cfg.TLS {
			scheme = "https"
		}
		sameOrigin := func(origin string) bool {
			return strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(origin), "/"), scheme+"://"+r.Host)
		}
		if origin := r.Header.Get("Origin"); origin != "" && !sameOrigin(origin) && !originAllowed(origin, cfg.AllowedOrigins) {
			deny("cross-origin request")
			return
		}
		if sfs := strings.ToLower(r.Header.Get("Sec-Fetch-Site")); sfs == "cross-site" || (sfs == "same-site" && !sameOrigin(r.Header.Get("Origin"))) {
			if !originAllowed(r.Header.Get("Origin"), cfg.AllowedOrigins) {
				deny("cross-site request")
				return
			}
		}
		if r.Method == http.MethodOptions && r.Header.Get("Origin") == "" {
			deny("preflight request")
			return
		}
		if !cfg.AllowSelf && isSelfIP(ip, self) {
			deny("request from this node itself (set allow_self to accept)")
			return
		}
		if !cfg.ForwardManagement && IsManagementPath(r.URL.Path) {
			deny("management paths are not forwarded on the tailnet listener")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), o.Timeout)
		id, err := o.Whois.WhoIs(ctx, r.RemoteAddr)
		cancel()
		if err != nil {
			if errors.Is(err, ErrPeerNotFound) {
				deny("not a tailnet peer")
				return
			}
			logf("warn", "tailscale-identity: whois failed", map[string]any{"error": err.Error(), "remote": r.RemoteAddr})
			http.Error(w, "tailnet identity lookup failed", http.StatusServiceUnavailable)
			return
		}
		principal, err := cfg.Principal(id)
		if err != nil {
			logf("info", "tailscale-identity: peer rejected", map[string]any{"reason": err.Error(), "login": id.Login, "node": id.Node, "tags": id.Tags})
			http.Error(w, "forbidden: "+err.Error(), http.StatusForbidden)
			return
		}
		if cfg.LogRequests {
			logf("info", "tailscale-identity: request", map[string]any{
				"principal": maskPrincipal(principal), "login": id.Login, "node": id.Node, "tags": id.Tags,
				"remote": ip, "method": r.Method, "path": r.URL.Path,
			})
		}
		ri := &requestIdentity{Identity: id, Principal: principal, IP: ip}
		rp.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, ri)))
	})
}

// maskPrincipal hides most of a principal in logs. A principal is often a
// client API key, so logs must not hold it in full.
func maskPrincipal(p string) string {
	if len(p) <= 12 {
		return p
	}
	return p[:6] + "..." + p[len(p)-4:]
}
