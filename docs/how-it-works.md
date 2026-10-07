# How tailscale-identity works

This document is for contributors. It describes the components, the lifecycle, the request path, and the trust model of the plugin. For setup and configuration, see the [README](../README.md).

CPA means CLIProxyAPI. "The host" means the CPA plugin host (`internal/pluginhost` in the CPA source).

## Components and files

| File | Role |
|---|---|
| `main.go` | C ABI entry points. `cliproxy_plugin_init` fills the plugin API table. `cliproxyPluginCall` sends each JSON RPC call to `tsid.Plugin.Handle`. `cliproxyPluginShutdown` detaches the log sink and stops the plugin. `hostLog` calls the host `host.log` callback. |
| `internal/tsid/rpc.go` | `Plugin`: RPC dispatch, register and reconfigure, quiesce, shutdown, plugin metadata and capabilities, frontend auth entry point, the per-load secret. |
| `internal/tsid/config.go` | `Config`: parse, defaults, validation, `Equal`, and the principal rules. |
| `internal/tsid/mode.go` | `SelectMode`: choice between `system` and `embedded`, and the bind of the tailnet IPs in `system` mode. |
| `internal/tsid/runtime.go` | `Runtime`: one started config. Background start, retries, listeners, the monitor loop, stop, and the status report. |
| `internal/tsid/backend.go` | `Backend` interface, the LocalAPI adapter (`localClient`), WhoIs, certificates, and the `system` backend. |
| `internal/tsid/embedded.go` | The `embedded` backend (tsnet). Not in builds with the `tsid_noembed` tag. |
| `internal/tsid/embedded_stub.go` | Stub for `tsid_noembed` builds. `embedded` mode then fails with an error. |
| `internal/tsid/proxy.go` | The tailnet-facing HTTP handler: request policy, WhoIs, principal, header rewrite, reverse proxy. |
| `internal/tsid/auth.go` | `Authenticate`: the frontend auth decision, and the constant-time secret compare. |
| `internal/tsid/peers.go` | The tailnet peer list for the access editor. |
| `internal/tsid/management.go` | Management route and resource registration, and the management request handler. Embeds `status.html`. |
| `internal/tsid/status.html` | The plugin page: one static HTML file with inline CSS and script. |
| `internal/tsid/log.go` | Asynchronous log queue to the host. |

## Lifecycle

### Load and init

CPA loads the library with `dlopen` and calls `cliproxy_plugin_init`. The function gets the single `Plugin` value of the library image. A `sync.Once` creates it, together with a random 32-byte secret. The function then stores the host API pointer, installs the host log sink, and fills the plugin API table (ABI version 1).

`dlopen` of the same path returns the same image. Thus `cliproxy_plugin_init` can run again in one process. It then reuses the package state and clears the `closed` flag (`Reopen`).

### RPC methods

| Method | Effect |
|---|---|
| `plugin.register`, `plugin.reconfigure` | Parse `config_yaml`. If the config equals the current one and the runtime has not failed, keep the runtime. Else stop the old runtime (up to 10 seconds) and start a new one. Return the registration. |
| `plugin.quiesce` | Stop the runtime and keep the config. The host calls this before it retires the library. |
| `frontend_auth.identifier` | Return `tailscale-identity`. |
| `frontend_auth.authenticate` | Return the frontend auth result. See [Frontend auth contract](#frontend-auth-contract). |
| `management.register` | Return two management routes and one resource. Store the resource base path. |
| `management.handle` | Serve the routes and the page. |

The registration reports schema version 6 and the metadata: name, version, author, repository, and the config fields for the management UI. It also reports two capabilities: `frontend_auth_provider` and `management_api`. The plugin does not claim an exclusive frontend auth provider.

The host calls `plugin.register` again on every config apply. `Config.Equal` compares the YAML form of all plugin-owned fields. It ignores the host-owned keys `enabled`, `priority`, and `store`. Thus a store record change does not restart the listener, but any change to a plugin setting does.

A mutex (`lifecycle`) serializes register, quiesce, and shutdown. The old runtime always stops before the new one starts, so the port and the tsnet state directory are free.

### Shutdown

`cliproxyPluginShutdown` first calls `SetLogSink(nil)`. After that call returns, no host log call is in flight and none starts. The function then clears the stored host API pointer, because the host frees it after shutdown returns. Last, it sets `closed` and stops the runtime. After shutdown, `frontend_auth.authenticate` returns "not authenticated" and `plugin.register` fails.

### Background start

`StartRuntime` returns at once with the mode `starting`. A goroutine runs the start:

1. In `auto` and `system` mode, make a LocalAPI client for the host tailscaled.
2. Call `SelectMode`.
3. On a `RetryError`, set the mode to `waiting`, keep the reason, and sleep. The delay starts at 1 second and doubles up to 30 seconds. The plugin logs the reason only when it changes.
4. On another error, mark the runtime as failed. The next `plugin.register` call with the same config then starts a new runtime.
5. On success, reset the delay and serve the decision.

### Mode selection

`SelectMode` returns at once for `headers` and `embedded`. For `auto` and `system`, it reads the tailscaled status with a 3-second timeout:

| LocalAPI result | `auto` | `system` |
|---|---|---|
| Socket missing or connection refused | `embedded` | wait |
| Other error (permission, timeout) | wait | wait |
| Backend state not `Running` | wait | wait |
| No tailnet IP | wait | wait |
| No tailnet IP binds on `listen_port` | wait | wait |
| At least one tailnet IP binds | `system` | `system` |

`auto` never starts a second node on a host where tailscaled answers. A busy or restarting tailscaled must not cause a switch to `embedded`. The switch would add a new node to the tailnet.

In `system` mode, `SelectMode` binds every tailnet IP of the node on `listen_port`. The bind succeeds when at least one address binds. IPv6 bind failures are common.

### Serve and monitor

`serve` starts one `http.Server` per listener. `headers` mode has no listener, so the runtime ends after the selection. With `tls: true`, the server wraps each listener in TLS with `GetCertificate` from the backend, and offers `h2` and `http/1.1`. Each server has a 30-second header read timeout and a 120-second idle timeout. It has no write timeout, so long streams work.

The monitor loop then reads the backend status:

- every 30 seconds while the state is `Running`.
- every 3 seconds in another state, for example `NeedsLogin`.
- every 5 seconds after an error.

It logs each new login URL once and each change of the backend state. In `system` mode, it returns "bind again" when the tailnet IPs change or a listener fails. `run` then closes the servers and goes back to mode selection.

### Stop

`Runtime.Stop` is idempotent and bounded by its timeout (10 seconds from the plugin):

1. Cancel the start context. This ends retries and the monitor.
2. Call `Shutdown` on each server, with one third of the timeout as grace time.
3. Cancel the request context. This ends open streams and hijacked WebSocket connections.
4. Close the servers and the backend. In `embedded` mode this closes the tsnet node.
5. Wait for the goroutines until the deadline.

### Logging

`Logf` puts lines in a queue of 256 entries. One goroutine sends them to the host. Plugin calls thus never call the host back on the same stack. When the queue is full, the plugin drops new lines. The host log formatter shows only some field keys, so the plugin writes the fields into the message text as `key=value`. Without a host sink, lines go to stderr.

## Data path

### Request handling on the tailnet listener

For each request, the handler in `proxy.go` runs these steps in this order. Each failed check gives `403 forbidden: <reason>`.

1. **Host.** `Host` must be a tailnet IP of the node, its MagicDNS short name, its FQDN, its host name, or a name in `allowed_hosts`.
2. **Origin.** An `Origin` header must be the same origin (`http://` or `https://` plus `Host`) or be in `allowed_origins`.
3. **Sec-Fetch-Site.** `cross-site`, or `same-site` from another origin, needs an origin in `allowed_origins`.
4. **Preflight.** The handler rejects `OPTIONS` without `Origin`.
5. **Self.** The handler rejects a source IP that is a tailnet IP of this node, unless `allow_self: true`.
6. **Management paths.** The handler rejects management, plugin page, and OAuth callback paths, unless `forward_management: true`. The check uses the cleaned, lowercase path.
7. **WhoIs.** The backend resolves the source address with a 5-second timeout. An unknown address gives 403 `not a tailnet peer`. Another error gives `503 tailnet identity lookup failed`.
8. **Principal.** `Config.Principal` maps the identity. A rejection gives 403 with the reason.
9. **Proxy.** The request goes to the reverse proxy with the identity in its context.

The browser checks run before WhoIs. The Host check runs first, so a "same-origin" page is always a page that this listener served under a node name.

### Header rewrite

The reverse proxy sets the upstream URL (`SetURL`), so CPA sees the upstream host in `Host`. It then removes these client headers:

- `X-CPA-Tailnet-Login`, `X-CPA-Tailnet-Node`, `X-CPA-Tailnet-Principal`, `X-CPA-Tailnet-Secret`, and any other `X-CPA-Tailnet-*` header
- `Tailscale-User-Login`, `Tailscale-User-Name`, `Tailscale-User-Profile-Pic`, `Tailscale-App-Capabilities`, `Tailscale-Headers-Info`
- `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Real-Ip`, `Forwarded`

It then sets its own values:

| Header | Value |
|---|---|
| `X-CPA-Tailnet-Login` | login, URL-query-escaped. Empty for tagged nodes. |
| `X-CPA-Tailnet-Node` | MagicDNS name of the caller's node, escaped |
| `X-CPA-Tailnet-Principal` | resolved principal, escaped |
| `X-CPA-Tailnet-Secret` | the per-load secret |
| `X-Forwarded-For`, `X-Real-Ip` | tailnet IP of the caller |
| `X-Forwarded-Host` | original `Host` |
| `X-Forwarded-Proto` | `http`, or `https` with `tls` |

The proxy transport ignores `HTTP_PROXY` and related variables. It flushes each write at once (`FlushInterval: -1`), so SSE streams pass without buffering. `httputil.ReverseProxy` handles WebSocket upgrades.

On the response, the proxy removes every `Access-Control-*` header that CPA sets. For an origin in `allowed_origins`, it sets `Access-Control-Allow-Origin` to that origin. It also adds the allowed methods and headers, and `Vary: Origin`. An upstream error gives `502 upstream unavailable`.

## Identity resolution

`localClient.WhoIs` calls the LocalAPI WhoIs with the remote address and builds an `Identity`:

- `Node`: the node's computed name, or its FQDN without the trailing dot.
- `Tags` and `Tagged`: from the node.
- `Login`: the user profile login, only for nodes that are not tagged. A tagged node has no user, and Tailscale returns a placeholder profile for it.

`Config.Principal` then applies these rules:

1. If the node is tagged or has tags, sort the tags and return the `allow_tagged` value of the first tag that matches. If no tag matches, reject with `tagged node has no tag in allow_tagged`. Tagged nodes never use `principal_map`.
2. Else, lowercase and trim the login. An empty login gives `peer has no tailnet user identity`.
3. If the login is in `principal_map`, return its value.
4. If `require_mapping` is `true` (the default), reject with `login is not in principal_map`.
5. Else return the login as principal.

The parser lowercases `principal_map` keys. `allow_tagged` keys keep their case and must start with `tag:`. Empty principals fail validation.

## Frontend auth contract

CPA runs its access providers in order for each API request. For a plugin provider, the host calls `frontend_auth.authenticate` with the method, path, headers, query, and body. The host reads the body for this call and restores it. The plugin ignores the body.

The plugin returns `{Authenticated, Principal, Metadata}`. When `Authenticated` is false, the host reports "not handled", and CPA tries the next provider. When it is true, CPA sets `userApiKey` to `Principal`, `accessProvider` to `tailscale-identity`, and `accessMetadata` to `Metadata`.

`Authenticate` in `auth.go` decides:

- In `system`, `embedded`, and `auto` mode: the `X-CPA-Tailnet-Secret` header must equal the secret. The compare runs in constant time, and an empty secret never matches. The principal comes from `X-CPA-Tailnet-Principal`. Metadata: `source=tailscale`, `mode` (the active mode), `login`, `node`.
- In `headers` mode: the principal comes from `Tailscale-User-Login` through the user rules above. Metadata: `source=tailscale`, `mode=headers`, `login`.

### Why the secret header exists

The ABI gives the auth call the request headers but not the client address. The plugin thus cannot run WhoIs in the auth call. It runs WhoIs in its own proxy and passes the result to CPA in headers. Any process that reaches the CPA port could send the same headers. The secret proves that the request passed through the plugin's proxy, which removed all client copies first. The secret lives only in process memory and changes each time the library loads. Only the proxy and the auth call in the same library image know it.

`headers` mode has no proxy of its own, so it has no secret. It trusts `tailscale serve` and depends on CPA being reachable only through that proxy.

## Management routes and the plugin page

`management.register` returns:

| Kind | Path | Purpose |
|---|---|---|
| Route | `GET /v0/management/tailscale-identity/status` | Runtime status as JSON (`StatusReport`). |
| Route | `GET /v0/management/tailscale-identity/peers` | Tailnet peers as JSON (`PeersReport`). |
| Resource | `/v0/resource/plugins/tailscale-identity/status` | The plugin page, with the menu entry `Tailscale`. |

CPA checks the management key for routes. It does not check anything for resources. Thus the page is a static shell with no data. The handler serves it with `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and this CSP:

```
default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline';
connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'
```

`frame-ancestors 'self'` lets the management center show the page in a frame. Other methods on these paths get 405. Other paths get 404.

The status route reads the backend status with a 2-second timeout and falls back to the cached value. The peers route reads the full LocalAPI status with peers. In `headers` mode it asks the host tailscaled, which normally runs next to `tailscale serve`. The peers route never fails: an empty list comes with a reason. A peer has `shared: true` when it is in the netmap only because you shared the node with its owner.

### Page data flow

The page sends every call with `Authorization: Bearer <management key>`:

| Call | Use |
|---|---|
| `GET /v0/management/tailscale-identity/status` | Status card. Every 5 seconds while the tab is visible. Also the key test at start. |
| `GET /v0/management/tailscale-identity/peers` | Login choices and device summaries. |
| `GET /v8/management/config/plugins/configs/tailscale-identity` | Current plugin config. |
| `PUT /v8/management/config/plugins/configs/tailscale-identity` | Save. |
| `GET /v8/management/config/access/api-keys` | Client API key choices. |
| `GET /v8/management/config/plugins/configs/key-router` | Optional key names from key-router `users`. |
| `GET`, `PUT /v8/management/config/server/trusted-proxies` | Check and set trusted proxies when `forward_management` is on. |

A v8 config path that does not exist returns `404 {"error":"not_found"}`. The page then uses a default value.

Key discovery: the management center stores its login in `localStorage` key `cli-proxy-auth` when "remember" is on. The management center obfuscates the value with a key from the origin host and the user agent. The page is on the same origin, so it can read the value. It tries that key, then the key in `sessionStorage` (`tailscale-identity.key`), then asks the user. A 401 makes it try the next key or ask again.

Save: the page reads the newest plugin config, applies only the edited fields, and writes the object back. Default values become absent keys. Host-owned keys, secrets, and unknown keys stay. CPA writes `config.yaml` and applies the config, and the plugin restarts its listener if a plugin setting changed.

## Embedded mode (tsnet)

`newEmbeddedBackend` does these steps:

1. Create `state_dir` with mode 0700.
2. If `upload_logs` is `false`, call `logtail.Disable` one time. This affects only the Go runtime of this library image, not CPA.
3. Make a `tsnet.Server` with `Dir`, `Hostname`, `AuthKey`, `ClientSecret`, `AdvertiseTags`, `ControlURL`, and `Ephemeral` from the config.
4. Send tsnet user log lines to the CPA log. tsnet repeats the login URL line every few seconds, so the plugin drops a line that equals the line before it. Send tsnet debug logs to the CPA log only with `verbose_logs`.
5. Call `Start`. It does not wait for a login.
6. Get a LocalAPI client for the node, and listen on `:<listen_port>` on the tsnet node.

Login URL: tsnet puts the URL in the status as `AuthURL`. The monitor reads the status every 3 seconds while the state is not `Running`. It logs a new URL once as `tailscale-identity: login required, open this URL to add the node to your tailnet`. The status route and the page show the same URL.

State: the node key and the login live in `state_dir`. A restart of the runtime, of the library, or of CPA reuses them. Two runtimes never use the state directory at the same time, because the old runtime stops before the new one starts.

Ephemeral: with `ephemeral: true`, the control server removes the node soon after it goes offline. The next start then needs a new login, so use it with an auth key.

`auth_key` falls back to `TS_AUTHKEY`, then `TS_AUTH_KEY`. `client_secret` falls back to `TS_CLIENT_SECRET`. tsnet also reads other `TS_*` variables from the process environment.

## Hot reload and Go shared libraries

A Go `c-shared` library contains its own Go runtime. A Go runtime cannot stop, so CPA cannot unload the library. This has these effects:

- **New path for each version.** `dlopen` of a path that is already open returns the same image. CPA thus loads new code only from a new path. CPA also swaps a plugin only when the selected file path changes during a config apply. Release files therefore carry the version in the name.
- **Retire, not unload.** For a swap, CPA calls `plugin.quiesce` on the old image, loads the new image, and retires the old one. Quiesce stops the listener and the tsnet node, so the port and `state_dir` are free for the new image. The old Go runtime stays in memory until the process exits. Each swap thus adds the memory of one idle runtime.
- **Two runtimes in one process.** The old and the new image do not share Go state. Each has its own secret, log queue, and `logtail` setting. The secret check works because the proxy and the auth call of the active image use the same secret.
- **Disable is not stop.** `enabled: false` removes the plugin from the active set, but CPA does not call quiesce. The listener stays open until the next quiesce, shutdown, or process exit.

## Threat model

| Threat | Mitigation | Residual risk |
|---|---|---|
| A tailnet peer claims another identity in a header | The proxy removes all client identity and forwarding headers before it sets its own. | None known. |
| A process that reaches CPA directly sends identity headers | CPA accepts the identity only with the per-load secret. Bind CPA to loopback. | In `headers` mode there is no secret. CPA must be reachable only through `tailscale serve`. |
| A tailnet peer reaches CPA's loopback port through userspace tailscaled | Use a kernel TUN device. | The plugin cannot detect userspace networking. |
| A web page in a tailnet user's browser uses the user's identity | Host allow-list, Origin and Sec-Fetch-Site checks, preflight rejection, removal of `Access-Control-*` headers. | Origins in `allowed_origins` get full access as the user. |
| DNS rebinding to the tailnet listener | The `Host` header must name this node or be in `allowed_hosts`. | Names in `allowed_hosts` are trusted. |
| A local process on the CPA host uses the owner's identity through the host tailnet IP | Requests from a tailnet IP of the node are rejected unless `allow_self: true`. | With `allow_self: true`, every local process acts as the node owner. |
| A tailnet caller looks like a local admin to CPA management | Management, plugin page, and OAuth callback paths are blocked by default. With `forward_management`, set `server.trusted-proxies`. | With `forward_management` and no trusted proxies, tailnet callers skip `allow-remote` and share the ban bucket of `127.0.0.1`. The page and the log warn about this. |
| A tagged node (CI, server) gets access by accident | Tagged nodes need an explicit `allow_tagged` entry. | None known. |
| A user of another tailnet gets access through node sharing | `require_mapping: true` by default. | With `require_mapping: false`, the ACL and node sharing are the only control. |
| Someone opens the embedded login URL and adds the node to their tailnet | The URL appears only in the log and behind the management key. | Logs that hold the URL are sensitive. |
| A client API key leaks through logs | Request logs mask principals (first 6 and last 4 characters). | `config.yaml` holds the full keys in `principal_map`. |
| The secret leaks | It lives in process memory, changes on each load, and is in no response. | CPA receives it in a request header. A leaked secret is useless without a path to the CPA port. |
| A malicious plugin build | Checksums in releases, store checksum check. | The plugin runs in-process with full rights. Trust the source. |
