# Changelog

All notable changes to this plugin are listed here. Versions match the GitHub release tags.

## v0.2.0 - 2026-10-07

First public release.

### Added

- Tailnet identity auth for CLIProxyAPI. The plugin runs its own listener, gets the Tailscale identity of the caller with WhoIs, and maps the login or tag to a CLIProxyAPI principal. Mapped clients need no API key.
- Four modes:
  - `system`: use the tailscaled LocalAPI on the host.
  - `embedded`: run an embedded tsnet node in the CLIProxyAPI process.
  - `headers`: trust the identity headers from `tailscale serve` or a sidecar.
  - `auto`: use `system` when a tailscaled LocalAPI answers, else `embedded`.
- Status and access page under `/v0/resource/plugins/tailscale-identity/status`, in the management center menu as **Tailscale**. The page reads its data from management routes. It reuses the management key that the management center remembers, and asks for a key only when no saved key works.
- Access editor on the page: map tailnet logins to client API keys, and edit the main plugin options.
- `GET /v0/management/tailscale-identity/status` returns the runtime state as JSON. This includes the mode, backend state, node, tailnet IPs, login URL, and last error.
- `GET /v0/management/tailscale-identity/peers` returns the tailnet peers as JSON for the access editor.
- Optional management over the tailnet with `forward_management: true`.
- Plugin store packaging: one zip per platform and `checksums.txt` on each GitHub release.
- Release builds for linux/amd64, linux/arm64, darwin/arm64, and darwin/amd64. The Linux builds use Debian bookworm (glibc 2.36), the same base as the CLIProxyAPI image.

### Security

- The listener removes spoofable inbound identity headers and signs its own headers with a per-boot secret.
- The listener rejects requests from the node itself unless `allow_self: true`.
- The listener accepts only known Host names and same-origin browser requests by default.
- The proxy does not forward management, resource, and OAuth callback paths by default.
- Request logs mask long principals.
- `system` mode waits for a running tailscaled and does not start a second node.
