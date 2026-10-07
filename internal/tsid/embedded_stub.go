//go:build tsid_noembed

package tsid

import "errors"

// EmbeddedAvailable reports whether this build includes tsnet.
const EmbeddedAvailable = false

func newEmbeddedBackend(*Config) (Backend, error) {
	return nil, errors.New("this build has no embedded mode (built with tsid_noembed)")
}
