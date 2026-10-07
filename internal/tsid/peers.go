package tsid

import (
	"context"
	"sort"
	"strings"
	"time"

	"tailscale.com/ipn/ipnstate"
)

// PeersRoute is relative to /v0/management.
const PeersRoute = "/" + PluginID + "/peers"

// PeerInfo describes one tailnet node for the access editor.
type PeerInfo struct {
	Login       string   `json:"login"`        // owner login, empty for tagged nodes
	DisplayName string   `json:"display_name"` // owner display name
	Node        string   `json:"node"`         // host name
	DNSName     string   `json:"dns_name"`     // MagicDNS FQDN without the trailing dot
	OS          string   `json:"os,omitempty"`
	Online      bool     `json:"online"`
	Tags        []string `json:"tags"`
	Tagged      bool     `json:"tagged"`
	// Shared is true for a node that is in the netmap only because its
	// owner (often a user of another tailnet) got this node shared.
	Shared bool `json:"shared"`
}

// PeersReport is the payload of the peers route. Peers is never nil.
// Reason explains an empty list.
type PeersReport struct {
	BackendState     string     `json:"backend_state"`
	Reason           string     `json:"reason,omitempty"`
	OwnerLogin       string     `json:"owner_login"`
	OwnerDisplayName string     `json:"owner_display_name"`
	Self             *PeerInfo  `json:"self,omitempty"`
	Peers            []PeerInfo `json:"peers"`
}

// PeerLister is a backend that can list the tailnet peers. The system and
// embedded backends implement it through the LocalAPI client.
type PeerLister interface {
	Peers(ctx context.Context) (PeersReport, error)
}

// Peers reads the full status (with peers) from the LocalAPI. Read-only.
func (l *localClient) Peers(ctx context.Context) (PeersReport, error) {
	st, err := l.lc.Status(ctx)
	if err != nil {
		return PeersReport{}, err
	}
	return peersFromIPN(st), nil
}

// peersFromIPN converts an ipnstate.Status. It returns an empty list with a
// reason when the backend is not Running.
func peersFromIPN(st *ipnstate.Status) PeersReport {
	rep := PeersReport{BackendState: st.BackendState, Peers: []PeerInfo{}}
	profile := func(ps *ipnstate.PeerStatus) (string, string) {
		if ps == nil {
			return "", ""
		}
		u, ok := st.User[ps.UserID]
		if !ok {
			return "", ""
		}
		return u.LoginName, u.DisplayName
	}
	info := func(ps *ipnstate.PeerStatus) PeerInfo {
		pi := PeerInfo{
			Node:    ps.HostName,
			DNSName: strings.TrimSuffix(ps.DNSName, "."),
			OS:      ps.OS,
			Online:  ps.Online,
			Tags:    []string{},
			Tagged:  ps.IsTagged(),
			Shared:  ps.ShareeNode,
		}
		if ps.Tags != nil {
			pi.Tags = append(pi.Tags, ps.Tags.AsSlice()...)
		}
		if !pi.Tagged {
			pi.Login, pi.DisplayName = profile(ps)
		}
		return pi
	}
	if st.Self != nil {
		self := info(st.Self)
		rep.Self = &self
		rep.OwnerLogin, rep.OwnerDisplayName = profile(st.Self)
	}
	if st.BackendState != "Running" {
		rep.Reason = "tailnet backend state is " + nonEmpty(st.BackendState, "unknown")
		return rep
	}
	for _, ps := range st.Peer {
		if ps == nil {
			continue
		}
		rep.Peers = append(rep.Peers, info(ps))
	}
	sort.Slice(rep.Peers, func(i, j int) bool {
		a, b := rep.Peers[i], rep.Peers[j]
		if a.Login != b.Login {
			// Tagged nodes (no login) go last.
			if a.Login == "" || b.Login == "" {
				return b.Login == ""
			}
			return strings.ToLower(a.Login) < strings.ToLower(b.Login)
		}
		return a.Node < b.Node
	})
	if len(rep.Peers) == 0 {
		rep.Reason = "the tailnet has no other nodes that this node can see"
	}
	return rep
}

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// peerSource returns the backend that can list peers, or a reason.
func (r *Runtime) peerSource() (PeerLister, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	src := r.backend
	if src == nil {
		src = r.sys
	}
	if pl, ok := src.(PeerLister); ok && src != nil {
		return pl, ""
	}
	reason := "no tailnet backend yet (mode " + r.mode
	if r.reason != "" {
		reason += ": " + r.reason
	}
	return nil, reason + ")"
}

// Peers lists the tailnet peers for the management UI. It never fails: an
// empty list comes with a reason. In headers mode it asks the system
// tailscaled, which normally runs next to `tailscale serve`.
func (p *Plugin) Peers(ctx context.Context) PeersReport {
	p.mu.RLock()
	cfg, rt := p.cfg, p.rt
	p.mu.RUnlock()
	empty := func(reason string) PeersReport {
		return PeersReport{Reason: reason, Peers: []PeerInfo{}}
	}
	var src PeerLister
	switch {
	case rt == nil || cfg == nil:
		return empty("the plugin is stopped")
	case cfg.Mode == ModeHeaders:
		if p.deps.NewSystem == nil {
			return empty("headers mode has no tailnet backend")
		}
		be := p.deps.NewSystem(cfg)
		pl, ok := be.(PeerLister)
		if !ok {
			return empty("headers mode has no tailnet backend")
		}
		src = pl
	default:
		var reason string
		if src, reason = rt.peerSource(); src == nil {
			return empty(reason)
		}
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rep, err := src.Peers(cctx)
	if err != nil {
		return empty("tailnet status: " + err.Error())
	}
	if rep.Peers == nil {
		rep.Peers = []PeerInfo{}
	}
	return rep
}
