package tsid

import (
	"crypto/subtle"
	"net/http"
	"net/url"
)

// AuthResult mirrors pluginapi.FrontendAuthResponse.
type AuthResult struct {
	Authenticated bool              `json:"Authenticated"`
	Principal     string            `json:"Principal,omitempty"`
	Metadata      map[string]string `json:"Metadata,omitempty"`
}

// CanonicalHeader builds an http.Header from the host map with canonical keys.
func CanonicalHeader(in map[string][]string) http.Header {
	h := make(http.Header, len(in))
	for k, v := range in {
		ck := http.CanonicalHeaderKey(k)
		h[ck] = append(h[ck], v...)
	}
	return h
}

// SecretMatches compares in constant time. An empty expected secret never matches.
func SecretMatches(got, want string) bool {
	if want == "" || len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// Authenticate decides the frontend auth result for one request.
// A false result means "not handled": the host then tries the next provider,
// so built-in API keys keep working.
func Authenticate(cfg *Config, secret, activeMode string, h http.Header) AuthResult {
	if cfg == nil {
		return AuthResult{}
	}
	if cfg.Mode == ModeHeaders {
		login := h.Get(HeaderServeLogin)
		if login == "" {
			return AuthResult{}
		}
		principal, err := cfg.PrincipalForLogin(login)
		if err != nil {
			return AuthResult{}
		}
		return AuthResult{Authenticated: true, Principal: principal, Metadata: map[string]string{
			"source": "tailscale", "mode": ModeHeaders, "login": login,
		}}
	}
	if !SecretMatches(h.Get(HeaderSecret), secret) {
		return AuthResult{}
	}
	principal := unescape(h.Get(HeaderPrincipal))
	if principal == "" {
		return AuthResult{}
	}
	md := map[string]string{"source": "tailscale", "mode": activeMode}
	if v := unescape(h.Get(HeaderLogin)); v != "" {
		md["login"] = v
	}
	if v := unescape(h.Get(HeaderNode)); v != "" {
		md["node"] = v
	}
	return AuthResult{Authenticated: true, Principal: principal, Metadata: md}
}

func unescape(s string) string {
	v, err := url.QueryUnescape(s)
	if err != nil {
		return ""
	}
	return v
}
