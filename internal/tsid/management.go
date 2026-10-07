package tsid

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// StatusRoute is relative to /v0/management.
const StatusRoute = "/" + PluginID + "/status"

//go:embed status.html
var statusHTML []byte

type mgmtRoute struct {
	Method      string `json:"Method"`
	Path        string `json:"Path"`
	Menu        string `json:"Menu,omitempty"`
	Description string `json:"Description,omitempty"`
}

type mgmtResource struct {
	Path        string `json:"Path"`
	Menu        string `json:"Menu,omitempty"`
	Description string `json:"Description,omitempty"`
}

type mgmtRegisterRequest struct {
	BasePath         string `json:"BasePath"`
	ResourceBasePath string `json:"ResourceBasePath"`
}

type mgmtRegisterResult struct {
	Routes    []mgmtRoute    `json:"routes"`
	Resources []mgmtResource `json:"resources"`
}

func (p *Plugin) managementRegister(req []byte) (any, error) {
	var r mgmtRegisterRequest
	if len(req) > 0 {
		if err := json.Unmarshal(req, &r); err != nil {
			return nil, fmt.Errorf("decode management.register: %w", err)
		}
	}
	p.mu.Lock()
	p.resBase = strings.TrimRight(r.ResourceBasePath, "/")
	p.mu.Unlock()
	return mgmtRegisterResult{
		Routes: []mgmtRoute{
			{Method: "GET", Path: StatusRoute, Description: "Tailscale identity status (JSON)"},
			{Method: "GET", Path: PeersRoute, Description: "Tailnet peers for the access editor (JSON)"},
		},
		Resources: []mgmtResource{{Path: "/status", Menu: "Tailscale", Description: "Tailscale identity status and access page"}},
	}, nil
}

type mgmtRequest struct {
	Method string `json:"Method"`
	Path   string `json:"Path"`
}

type mgmtResponse struct {
	StatusCode int                 `json:"StatusCode"`
	Headers    map[string][]string `json:"Headers"`
	Body       []byte              `json:"Body"`
}

func (p *Plugin) managementHandle(req []byte) (any, error) {
	var r mgmtRequest
	if err := json.Unmarshal(req, &r); err != nil {
		return nil, fmt.Errorf("decode management.handle: %w", err)
	}
	method := strings.ToUpper(r.Method)
	if method == "" {
		method = "GET"
	}
	path := strings.TrimRight(r.Path, "/")
	p.mu.RLock()
	resBase := p.resBase
	p.mu.RUnlock()

	switch {
	case method == "GET" && path == "/v0/management"+StatusRoute:
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return jsonResponse(p.Report(ctx)), nil
	case method == "GET" && path == "/v0/management"+PeersRoute:
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		return jsonResponse(p.Peers(ctx)), nil
	case method == "GET" && isResource(path, resBase):
		// The resource is unauthenticated, so it is a static shell. Its
		// script reads the data from the authenticated management route.
		return mgmtResponse{StatusCode: 200, Headers: map[string][]string{
			"Content-Type":            {"text/html; charset=utf-8"},
			"Cache-Control":           {"no-store"},
			"X-Content-Type-Options":  {"nosniff"},
			"Referrer-Policy":         {"no-referrer"},
			"Content-Security-Policy": {"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'"},
		}, Body: statusHTML}, nil
	case isResource(path, resBase) || path == "/v0/management"+StatusRoute || path == "/v0/management"+PeersRoute:
		return mgmtResponse{StatusCode: 405, Headers: map[string][]string{"Content-Type": {"text/plain"}, "Allow": {"GET"}}, Body: []byte("method not allowed")}, nil
	}
	return mgmtResponse{StatusCode: 404, Headers: map[string][]string{"Content-Type": {"text/plain"}}, Body: []byte("not found")}, nil
}

func isResource(path, base string) bool {
	if base != "" {
		return path == base+"/status"
	}
	return strings.HasPrefix(path, "/v0/resource/plugins/") && strings.HasSuffix(path, "/status")
}

func jsonResponse(v any) mgmtResponse {
	body, _ := json.Marshal(v)
	return mgmtResponse{StatusCode: 200, Headers: map[string][]string{
		"Content-Type":  {"application/json"},
		"Cache-Control": {"no-store"},
	}, Body: body}
}
