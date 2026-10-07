package tsid

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"

	"tailscale.com/client/local"
	"tailscale.com/ipn/ipnstate"
)

// Identity is the result of a WhoIs lookup.
type Identity struct {
	Login  string
	Node   string // MagicDNS base name, or FQDN without the trailing dot
	Tags   []string
	Tagged bool
}

// BackendStatus is the subset of ipnstate.Status the plugin uses.
type BackendStatus struct {
	BackendState string
	AuthURL      string
	HostName     string
	DNSName      string
	TailscaleIPs []netip.Addr
	CertDomains  []string
}

// ErrPeerNotFound is returned by WhoIs when the address is not a tailnet peer.
var ErrPeerNotFound = errors.New("peer not found in tailnet")

// LocalAPI is the read-only part of a tailscaled LocalAPI client.
type LocalAPI interface {
	StatusWithoutPeers(ctx context.Context) (BackendStatus, error)
}

// Backend is a tailnet node the plugin listens on.
type Backend interface {
	LocalAPI
	Name() string
	WhoIs(ctx context.Context, remoteAddr string) (Identity, error)
	Listen(port int) ([]net.Listener, error)
	GetCertificate(hi *tls.ClientHelloInfo) (*tls.Certificate, error)
	Close() error
}

// localClient adapts tailscale.com/client/local.Client.
type localClient struct {
	lc *local.Client

	mu         sync.Mutex
	certDomain string
}

func (l *localClient) StatusWithoutPeers(ctx context.Context) (BackendStatus, error) {
	st, err := l.lc.StatusWithoutPeers(ctx)
	if err != nil {
		return BackendStatus{}, err
	}
	bs := statusFromIPN(st)
	if len(bs.CertDomains) > 0 {
		l.mu.Lock()
		l.certDomain = bs.CertDomains[0]
		l.mu.Unlock()
	}
	return bs, nil
}

func (l *localClient) WhoIs(ctx context.Context, remoteAddr string) (Identity, error) {
	w, err := l.lc.WhoIs(ctx, remoteAddr)
	if err != nil {
		if errors.Is(err, local.ErrPeerNotFound) {
			return Identity{}, ErrPeerNotFound
		}
		return Identity{}, err
	}
	id := Identity{}
	if w.Node != nil {
		id.Node = w.Node.ComputedName
		if id.Node == "" {
			id.Node = strings.TrimSuffix(w.Node.Name, ".")
		}
		id.Tags = append(id.Tags, w.Node.Tags...)
		id.Tagged = w.Node.IsTagged()
	}
	if w.UserProfile != nil && !id.Tagged {
		id.Login = w.UserProfile.LoginName
	}
	return id, nil
}

// GetCertificate fetches the node certificate. Clients that connect by IP
// send no SNI, so the first cert domain is used then.
func (l *localClient) GetCertificate(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hi.ServerName == "" {
		l.mu.Lock()
		d := l.certDomain
		l.mu.Unlock()
		if d == "" {
			return nil, errors.New("no SNI and no tailnet cert domain known yet")
		}
		cp := *hi
		cp.ServerName = d
		hi = &cp
	}
	return l.lc.GetCertificate(hi)
}

func statusFromIPN(st *ipnstate.Status) BackendStatus {
	bs := BackendStatus{
		BackendState: st.BackendState,
		AuthURL:      st.AuthURL,
		TailscaleIPs: append([]netip.Addr(nil), st.TailscaleIPs...),
		CertDomains:  append([]string(nil), st.CertDomains...),
	}
	if st.Self != nil {
		bs.HostName = st.Self.HostName
		bs.DNSName = strings.TrimSuffix(st.Self.DNSName, ".")
	}
	return bs
}

// systemBackend uses the tailscaled already running on the host.
type systemBackend struct {
	*localClient
}

func newSystemBackend(cfg *Config) *systemBackend {
	return &systemBackend{&localClient{lc: &local.Client{Socket: cfg.Socket, UseSocketOnly: cfg.UseSocketOnly}}}
}

func (s *systemBackend) Name() string { return ModeSystem }

// Listen is not used in system mode: selectMode binds the tailnet IPs.
func (s *systemBackend) Listen(port int) ([]net.Listener, error) {
	return nil, errors.New("system backend listeners come from mode selection")
}

func (s *systemBackend) Close() error { return nil }
