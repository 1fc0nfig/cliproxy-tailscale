package tsid

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Binder opens a TCP listener. net.Listen in production.
type Binder func(network, addr string) (net.Listener, error)

// Decision is the result of mode selection.
type Decision struct {
	Mode      string
	Reason    string
	Status    BackendStatus
	Listeners []net.Listener // system mode only
}

const probeTimeout = 3 * time.Second

// RetryError means system mode is not ready yet: tailscaled answers but is
// not Running, has no tailnet IP, or the port does not bind. The caller
// retries. It never falls back to embedded mode.
type RetryError struct {
	Reason string
	Status BackendStatus
}

func (e *RetryError) Error() string { return "system mode not ready: " + e.Reason }

// LocalAPIAbsent reports whether err means that no tailscaled LocalAPI
// exists: the socket is missing or the connection is refused. Timeouts and
// other errors do not count: tailscaled can be busy or restarting.
func LocalAPIAbsent(err error) bool {
	return errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, fs.ErrNotExist) || errors.Is(err, errNoLocalAPI)
}

var errNoLocalAPI = errors.New("no LocalAPI")

// SelectMode decides between system and embedded mode.
// For system mode it also binds the tailnet IPs, so "bindable" is proven by
// the listeners it returns. Headers and embedded mode need no probe.
//
// auto selects embedded only when the LocalAPI is absent. When tailscaled
// answers but is not ready, SelectMode returns a *RetryError in both auto
// and system mode, so a host that runs tailscaled never gets a second node.
func SelectMode(ctx context.Context, cfg *Config, api LocalAPI, bind Binder) (Decision, error) {
	switch cfg.Mode {
	case ModeHeaders:
		return Decision{Mode: ModeHeaders, Reason: "configured"}, nil
	case ModeEmbedded:
		return Decision{Mode: ModeEmbedded, Reason: "configured"}, nil
	}
	pctx, cancel := context.WithTimeout(ctx, probeTimeout)
	st, err := api.StatusWithoutPeers(pctx)
	cancel()
	switch {
	case err != nil:
		if cfg.Mode == ModeAuto && LocalAPIAbsent(err) {
			return Decision{Mode: ModeEmbedded, Reason: "no tailscaled LocalAPI: " + err.Error()}, nil
		}
		return Decision{}, &RetryError{Reason: "tailscaled LocalAPI did not answer: " + err.Error()}
	case st.BackendState != "Running":
		return Decision{}, &RetryError{Reason: "tailscaled backend state is " + st.BackendState, Status: st}
	case len(st.TailscaleIPs) == 0:
		return Decision{}, &RetryError{Reason: "tailscaled has no tailnet IPs", Status: st}
	}
	lns, berr := bindTailnetIPs(st, cfg.ListenPort, bind)
	if berr != nil {
		return Decision{}, &RetryError{Reason: berr.Error(), Status: st}
	}
	return Decision{Mode: ModeSystem, Reason: "tailscaled is running as " + st.DNSName, Status: st, Listeners: lns}, nil
}

// bindTailnetIPs listens on every tailnet IP. It succeeds when at least one
// address binds. IPv6 failures are common and only logged by the caller.
func bindTailnetIPs(st BackendStatus, port int, bind Binder) ([]net.Listener, error) {
	var lns []net.Listener
	var errs []string
	for _, ip := range st.TailscaleIPs {
		addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
		ln, err := bind("tcp", addr)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		lns = append(lns, ln)
	}
	if len(lns) == 0 {
		return nil, fmt.Errorf("cannot bind a tailnet IP on port %d: %s", port, strings.Join(errs, "; "))
	}
	return lns, nil
}
