//go:build !tsid_noembed

package tsid

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"

	"tailscale.com/logtail"
	"tailscale.com/tsnet"
)

// EmbeddedAvailable reports whether this build includes tsnet.
const EmbeddedAvailable = true

var disableLogUpload sync.Once

// embeddedBackend runs its own tailnet node with tsnet inside the plugin.
type embeddedBackend struct {
	*localClient
	srv *tsnet.Server
}

func newEmbeddedBackend(cfg *Config) (Backend, error) {
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("state_dir: %w", err)
	}
	if !cfg.UploadLogs {
		// Process-global inside the plugin runtime only.
		disableLogUpload.Do(logtail.Disable)
	}
	var lastLine string
	var lastMu sync.Mutex
	srv := &tsnet.Server{
		Dir:           cfg.StateDir,
		Hostname:      cfg.Hostname,
		AuthKey:       cfg.AuthKey,
		ClientSecret:  cfg.ClientSecret,
		AdvertiseTags: cfg.AdvertiseTags,
		ControlURL:    cfg.ControlURL,
		Ephemeral:     cfg.Ephemeral,
		UserLogf: func(format string, args ...any) {
			// tsnet repeats the login URL line every few seconds. Log it once.
			line := fmt.Sprintf(format, args...)
			lastMu.Lock()
			dup := line == lastLine
			lastLine = line
			lastMu.Unlock()
			if !dup {
				Logf("info", "tsnet: "+line, nil)
			}
		},
	}
	if cfg.VerboseLogs {
		srv.Logf = func(format string, args ...any) {
			Logf("debug", "tsnet: "+fmt.Sprintf(format, args...), nil)
		}
	} else {
		srv.Logf = func(string, ...any) {}
	}
	// Start does not block on login. The login URL shows up in the status.
	if err := srv.Start(); err != nil {
		return nil, err
	}
	lc, err := srv.LocalClient()
	if err != nil {
		_ = srv.Close()
		return nil, err
	}
	return &embeddedBackend{localClient: &localClient{lc: lc}, srv: srv}, nil
}

func (e *embeddedBackend) Name() string { return ModeEmbedded }

func (e *embeddedBackend) Listen(port int) ([]net.Listener, error) {
	ln, err := e.srv.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return nil, err
	}
	return []net.Listener{ln}, nil
}

func (e *embeddedBackend) Close() error { return e.srv.Close() }
