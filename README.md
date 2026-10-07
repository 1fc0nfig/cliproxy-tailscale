# tailscale-identity

A CLIProxyAPI (CPA) plugin that lets users on your tailnet call CPA without an API key.

The plugin runs its own listener on the tailnet. For each request, it asks Tailscale who the caller is (WhoIs). It then maps the caller's login or tag to a CPA principal. CPA uses that principal as `userApiKey`. Usage records, session affinity, and plugins such as key-router thus see one stable identity per person. The Tailscale ACL controls who can reach the node. The plugin controls which of those callers get access, and as whom.

Plugin ID: `tailscale-identity`. Current version: 0.2.0. License: MIT.

## Contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Install](#install)
- [First-run setup](#first-run-setup)
- [Modes](#modes)
- [Using the plugin page](#using-the-plugin-page)
- [Management over the tailnet](#management-over-the-tailnet)
- [Using with key-router](#using-with-key-router)
- [Configuration reference](#configuration-reference)
- [Security model](#security-model)
- [Troubleshooting](#troubleshooting)
- [Limits](#limits)
- [Building and releasing](#building-and-releasing)
- [License](#license)

For the internal design, see [docs/how-it-works.md](docs/how-it-works.md).

## How it works

The CPA plugin ABI gives a frontend auth plugin the method, path, headers, query, and body of a request. It does not give the client IP address. So the plugin cannot run WhoIs inside the auth call. Instead, it puts its own listener in front of CPA:

```
tailnet peer (alice's laptop)
   |  http://cliproxy:8318/v1/chat/completions   (no API key)
   v
plugin listener (tailnet IP, port 8318)
   1. request policy: Host, Origin, self, management paths
   2. WhoIs(source address)  -> login alice@github, or tags
   3. policy: principal_map / allow_tagged / require_mapping  -> 403 or principal
   4. remove client identity headers, add X-CPA-Tailnet-* and the secret header
   v
reverse proxy  ->  CPA on 127.0.0.1:8317
                     frontend auth: the plugin checks the secret header
                     principal = userApiKey  (for example sk-example-alice)
```

The secret is a random value that the plugin makes when it loads. Only the plugin's own proxy knows it. A request that does not come through the proxy has no valid secret, so the plugin does not authenticate it. CPA then tries its other auth providers, so the built-in `api-keys` keep working.

The proxy streams responses without buffering (SSE) and passes WebSocket upgrades.

## Requirements

- **CPA v8.0.0 or later**, built with cgo. The plugin reports plugin schema version 6, and the plugin page uses the `/v8/management` config routes. Both are in v8.0.0. The upstream Docker image (`eceasy/cli-proxy-api`) uses a cgo build.
- `plugins.enabled: true` in the CPA config.
- One of these platforms:

  | OS | Architectures | Notes |
  |---|---|---|
  | Linux | amd64, arm64 | glibc 2.34 or later. Built on Debian bookworm, the base of the CPA image. musl (Alpine) is not supported. |
  | macOS | arm64, amd64 | macOS 12 or later. |
  | Windows | none | There is no Windows build. |

- One Tailscale source, depending on the [mode](#modes):
  - `system`: a tailscaled that runs on the same host, with read access to its LocalAPI.
  - `embedded`: nothing. The plugin runs its own tailnet node in the CPA process.
  - `headers`: `tailscale serve` or a Tailscale sidecar in front of CPA, with a kernel TUN device.

## Install

### A. Plugin store (management center)

From the official store, after the store lists this plugin:

1. Open the CPA management center.
2. Open the plugin store and find **Tailscale Identity**.
3. Click install.

From this repository, before the official listing, or to get releases sooner:

1. Add this registry to the CPA config:

   ```yaml
   plugins:
     enabled: true
     store-sources:
       - "https://raw.githubusercontent.com/1fc0nfig/cliproxy-tailscale/main/registry.json"
   ```

2. Open the plugin store in the management center and install **Tailscale Identity**.

The store downloads the zip for your platform from the GitHub release and verifies it against `checksums.txt`. It writes the library to `plugins/<goos>/<goarch>/tailscale-identity-v<version>.<ext>`. It also sets `plugins.configs.tailscale-identity.enabled: true`, records the version under `plugins.configs.tailscale-identity.store`, and reloads the config. The store does not change the global `plugins.enabled`.

### B. Manual download from GitHub Releases

Each release has one zip per platform and a `checksums.txt` file. Each zip holds one file, `tailscale-identity.so` or `tailscale-identity.dylib`.

1. Download the zip for your platform and `checksums.txt`:

   ```sh
   V=0.2.0
   P=linux_amd64   # linux_amd64, linux_arm64, darwin_arm64, darwin_amd64
   base=https://github.com/1fc0nfig/cliproxy-tailscale/releases/download/v$V
   curl -fLO "$base/tailscale-identity_${V}_${P}.zip"
   curl -fLO "$base/checksums.txt"
   ```

2. Verify the checksum:

   ```sh
   sha256sum --ignore-missing -c checksums.txt     # Linux
   shasum -a 256 --ignore-missing -c checksums.txt  # macOS
   ```

3. Unzip the library and copy it into the CPA plugin directory under a versioned name:

   ```sh
   unzip tailscale-identity_${V}_${P}.zip
   mkdir -p plugins/linux/amd64
   cp tailscale-identity.so plugins/linux/amd64/tailscale-identity-v$V.so
   ```

4. Add the plugin config (see [First-run setup](#first-run-setup)) and start CPA, or change the config of a running CPA.

The file name must be `tailscale-identity-v<version>.<ext>`. CPA reads the plugin ID and the version from the file name. It looks in `plugins/<goos>/<goarch>/` first, then in `plugins/`. When there are many versions, CPA picks the highest one, unless `store.version` pins a version.

### C. Docker

The upstream image runs CPA from `/CLIProxyAPI` and keeps auth files in `/root/.cli-proxy-api`.

- Mount a host directory on `/CLIProxyAPI/plugins`. Store installs then survive a container rebuild. The upstream `docker-compose.yml` already does this.
- In `embedded` mode, keep the node state on a volume. The default `state_dir` is `/root/.cli-proxy-api/tailscale` when `/root/.cli-proxy-api` exists. If you mount your auths volume there, the node state lives next to your auth files and survives a rebuild. Without a volume, the node needs a new login after each rebuild.
- In `system` mode, use host networking and mount the directory `/var/run/tailscale`, not the socket file. tailscaled makes a new socket file when it restarts, and a file mount keeps the old one.
- If you bind-mount `config.yaml` as a single file, see [Troubleshooting](#config-changes-on-the-host-do-not-reach-the-container).

`deploy/compose.example.yaml` has one profile per mode. `deploy/Dockerfile.example` builds an image with the plugin included.

## First-run setup

1. Bind CPA to loopback, so that tailnet callers can reach it only through the plugin:

   ```yaml
   server:
     host: "127.0.0.1"
     port: 8317
   ```

   In `embedded` mode with a published Docker port, you can keep `server.host: ""`. See [Security model](#security-model).

2. Turn on plugins and the plugin:

   ```yaml
   plugins:
     enabled: true
     configs:
       tailscale-identity:
         enabled: true
         mode: auto
   ```

   A store install sets `enabled: true` for you.

3. Choose a mode. `auto` uses `system` when a tailscaled LocalAPI exists, else `embedded`. See [Modes](#modes).

4. Open the plugin page: in the management center, open the **Tailscale** menu entry. You can also open `http://127.0.0.1:8317/v0/resource/plugins/tailscale-identity/status` directly. The page needs the management key.

5. If the status shows `backend_state: NeedsLogin` (embedded mode only), log the node in. Use one of these methods:
   - Click the login link on the status page.
   - Find the log line `tailscale-identity: login required, open this URL to add the node to your tailnet auth_url=https://login.tailscale.com/a/...`. In Docker, use `docker logs <container>`.
   - Set `auth_key` (or the environment variable `TS_AUTHKEY`) to a Tailscale auth key. Use a pre-approved, tagged key for servers.
   - Set `client_secret` (or `TS_CLIENT_SECRET`) to an OAuth client secret, and set `advertise_tags`. tsnet then makes an auth key with these tags.

   Wait until the status shows `backend_state: Running`.

6. Map users on the Access part of the page. Choose a tailnet login, choose the client API key that the login acts as, and click **Add**. Then click **Save**. With the default `require_mapping: true`, the proxy rejects every login that has no mapping.

7. Test from another tailnet device. Do not send an API key:

   ```sh
   curl http://cliproxy:8318/v1/models
   ```

   Use the MagicDNS name of the CPA node. In `system` mode that is the host's name. In `embedded` mode it is `hostname` (default `cliproxy`). A request from the CPA host itself gets 403 unless `allow_self: true`.

8. To see the identity of each request, turn on **Log each request** (`log_requests: true`). The log then shows `tailscale-identity: request` with the login and the masked principal, and `tailscale-identity: frontend auth` with the principal that CPA gets.

## Modes

| Mode | Tailnet node | Plugin listener | Choose it when |
|---|---|---|---|
| `system` | the tailscaled on the host | every tailnet IP of the host, `listen_port` | the host already runs Tailscale |
| `embedded` | a new node in the CPA process (tsnet, userspace) | the tsnet node, `listen_port` | a container or a host without Tailscale, or you want a separate node name |
| `headers` | none. `tailscale serve` or a sidecar is in front | none | Tailscale already proxies to CPA and you accept its trust model |
| `auto` (default) | `system` if a tailscaled LocalAPI exists, else `embedded` | as the selected mode | you want the plugin to decide |

### auto and system

`auto` selects `embedded` only when no tailscaled LocalAPI exists: the socket is missing or the connection is refused. When tailscaled answers, `auto` uses `system` mode. Then it waits until all of these conditions are true:

1. The backend state is `Running`.
2. The node has a tailnet IP.
3. The plugin can bind at least one tailnet IP on `listen_port`.

While it waits, the status shows `mode: waiting`, and `last_error` gives the reason. The plugin tries again after 1 second and doubles the delay up to 30 seconds. `system` mode waits in the same way. Thus a host that runs tailscaled never gets a second node, also when CPA starts before tailscaled. Other LocalAPI errors, for example "permission denied" or a timeout, also cause a wait and not a switch to `embedded`.

In `system` mode, the plugin checks the tailnet IPs every 30 seconds. When they change, or when a listener fails, it binds again.

The process needs read access to the tailscaled LocalAPI. A normal user has read access on Linux and macOS. On macOS, the LocalAPI client first looks for the Tailscale GUI app, then for the socket. If a Mac runs two tailscaled backends (GUI app and Homebrew), set `socket` and `use_socket_only: true` to select the socket backend. The log line `tailscale-identity: mode selected` shows which node the plugin uses.

If the host runs tailscaled in userspace mode (`--tun=userspace-networking`), tailnet peers can also reach `127.0.0.1:8317` through the tailnet IP. They still need an API key there, but the CPA management API sees them as local callers. Use a kernel TUN device on hosts that run CPA.

### embedded

The plugin starts a tsnet node with the name `hostname` and keeps its state in `state_dir`. The node needs a login one time. After that, a restart reuses the state. With `ephemeral: true`, the control server removes the node soon after it goes offline.

The node logs in as the user who opens the login URL, or as the tags of the auth key. This changes only the identity of the server node. The identity of each caller still comes from WhoIs.

### headers

In `headers` mode the plugin opens no listener. `tailscale serve` (or a sidecar) proxies `https://<node>/` to CPA and sets `Tailscale-User-Login` for user nodes. The plugin trusts this header without a check. Any process that can reach CPA directly can set it.

Requirements for `headers` mode:

1. Bind CPA to `127.0.0.1`. Only the Tailscale proxy may share that loopback.
2. Run tailscaled with a kernel TUN device. Do not use `TS_USERSPACE=true` or `--tun=userspace-networking`.
3. Point `tailscale serve` at `http://127.0.0.1:8317`. `deploy/serve.json` is an example.

The reason for item 2: for a tailnet port without a serve handler, userspace tailscaled forwards the connection to `127.0.0.1:<port>`. A peer can then call `http://<node>:8317/` directly, skip `tailscale serve`, and set `Tailscale-User-Login` to any login. A kernel TUN device does not forward to loopback. The plugin cannot detect how tailscaled runs, so you must check it. The `headers` profile in `deploy/compose.example.yaml` uses a kernel TUN device.

`tailscale serve` does not send `Tailscale-User-Login` for tagged nodes. Thus tagged nodes cannot authenticate in this mode, and `allow_tagged` has no effect.

`headers` mode is not yet tested end to end.

## Using the plugin page

The page is at `/v0/resource/plugins/tailscale-identity/status`. The management center shows it under the **Tailscale** menu entry. CPA serves plugin pages without authentication, so the page itself holds no data. Its script reads all data from management routes with the management key.

### Management key

The page first tries the key that the management center remembers in this browser (when "remember password" is on). It then tries a key that you entered earlier in this browser tab. If no key works, it asks for one. The key that you type stays in `sessionStorage` of the tab only. **Use another management key** clears it.

The browser stores the remembered key per origin. If you open the page over the tailnet, you log in again on that origin.

### Status

The Status card shows the active mode, the configured mode, and the reason for the selection. It also shows the backend state, the node name, the DNS name, and the tailnet IPs. The last rows are the listen addresses, TLS, the upstream, the login URL, and the last error. The card refreshes every 5 seconds. When the state is `NeedsLogin`, a notice shows the login URL as a link.

### Access

The Access card edits `principal_map` and some options:

- **Mappings**: one row per tailnet login, with the principal that the login acts as. The page shows the devices and online state of each login from the tailnet peer list.
- **Add mapping**: choose a login from the tailnet peers, or type one with **Other login**. Then choose a client API key from `access.api-keys`, or type a custom principal. Key names come from the key-router config when it exists. The page masks keys.
- **Options**: `require_mapping`, `log_requests`, and `forward_management`. With `forward_management` on, the page checks `server.trusted-proxies` and offers to add `127.0.0.1` and `::1`.
- **Advanced**: `mode`, `hostname`, `listen_port`, `tls`, `allow_self`, `allowed_origins`, and `allowed_hosts`.

The page does not edit `allow_tagged`, the embedded login settings, `socket`, `use_socket_only`, `state_dir`, `upstream`, or the log settings. Edit those in `config.yaml`.

### What Save does

1. The page reads the newest `plugins.configs.tailscale-identity` object.
2. It changes only the fields that you edited. It writes default values as absent keys. `enabled`, `priority`, `store`, secrets, and unknown keys stay as they are.
3. It writes the object back with `PUT /v8/management/config/plugins/configs/tailscale-identity`. CPA saves `config.yaml` and reloads the config.
4. The plugin compares the new config with the old one. If a plugin setting changed, it stops the listener and starts it again. Open streams and WebSocket connections end. In `embedded` mode the node restarts from its saved state, with no new login.

If you opened the page over the tailnet, it loses the connection for a moment and then reconnects.

The **Add 127.0.0.1 and ::1 to trusted-proxies** button writes `server.trusted-proxies`. CPA reads that setting only at start, so restart CPA after you use the button.

## Management over the tailnet

By default the proxy does not forward these paths, and it answers 403:

- `/v0/management`, `/v8/management`
- `/v0/resource` (plugin pages)
- `/management.html` (the management center)
- OAuth callbacks: `/anthropic/callback`, `/codex/callback`, `/antigravity/callback`, `/devin/callback`, `/callback`

To use the management center over the tailnet:

1. Set `forward_management: true`.
2. Set `server.trusted-proxies: ["127.0.0.1", "::1"]` in CPA.
3. Set `management.allow-remote: true` and a `management.secret-key` in CPA.
4. Restart CPA.
5. Open `http://cliproxy:8318/management.html` from a tailnet device and log in with the management key.

Why step 2 is necessary: every request from the proxy reaches CPA from `127.0.0.1`. Without trusted proxies, CPA sees every tailnet caller as a local caller. It then skips the `allow-remote` check and accepts the local password. It also counts the failed logins of all tailnet callers under `127.0.0.1`. Five bad keys then lock out the local admin for 30 minutes. With trusted proxies, CPA reads the real tailnet IP from `X-Forwarded-For`, which the proxy sets.

The plugin cannot read `server.trusted-proxies` without a side effect. Thus it logs a warning at start when `forward_management` is on. The plugin page checks the setting and shows a warning.

The management key is still required. The tailnet identity does not log a user in to management.

## Using with key-router

key-router identifies a caller by `caller_scope`, the SHA-256 hash of `userApiKey`. This plugin sets `userApiKey` to the mapped principal. Map a login to a client API key that key-router knows. key-router then routes that person to their own credentials. The person needs no key on their device.

1. Add a client API key per person to `access.api-keys`, for example `sk-example-alice`.
2. Assign that key to the person's credentials in the key-router config.
3. On the plugin page, map `alice@github` to that key.

Requests from any of Alice's tailnet devices then use Alice's credentials. Usage records also count them under Alice's key. If Alice also sends a valid API key, that key usually wins. See [Security model](#security-model).

## Configuration reference

All keys are under `plugins.configs.tailscale-identity`.

| Key | Type | Default | Effect |
|---|---|---|---|
| `enabled` | bool | `false` | Owned by CPA. Loads the plugin. |
| `priority` | int | `0` | Owned by CPA. Order among plugins. |
| `store` | object | none | Owned by CPA. Store install record. `store.version` pins the library version. |
| `mode` | string | `auto` | `auto`, `system`, `embedded`, or `headers`. |
| `listen_port` | int | `8318`, or `443` with `tls` | Tailnet port of the plugin listener. Not used in `headers` mode. |
| `tls` | bool | `false` | Serve HTTPS with the tailnet certificate. Needs MagicDNS and HTTPS certificates in the tailnet. |
| `upstream` | string | `http://127.0.0.1:8317` | CPA URL that the proxy forwards to. Must be `http` or `https`. |
| `socket` | string | per OS | `system`: tailscaled socket path. |
| `use_socket_only` | bool | `false` | `system`: skip the macOS GUI app discovery and use `socket`. |
| `hostname` | string | `cliproxy` | `embedded`: node name in the tailnet. |
| `state_dir` | string | see below | `embedded`: node state directory. `~` expands to the home directory. Created with mode 0700. |
| `auth_key` | string | `TS_AUTHKEY` or `TS_AUTH_KEY` | `embedded`: Tailscale auth key for login without a browser. |
| `client_secret` | string | `TS_CLIENT_SECRET` | `embedded`: OAuth client secret. tsnet makes an auth key with `advertise_tags`. |
| `advertise_tags` | list | empty | `embedded`: tags for the node. Required with `client_secret`. |
| `control_url` | string | Tailscale | `embedded`: other control server, for example Headscale. |
| `ephemeral` | bool | `false` | `embedded`: register an ephemeral node. |
| `upload_logs` | bool | `false` | `embedded`: when `false`, tsnet does not upload logs to `log.tailscale.com`. |
| `verbose_logs` | bool | `false` | `embedded`: send tsnet debug logs to the CPA log. |
| `principal_map` | map | empty | Login to principal. Keys are case-insensitive. Values must not be empty. |
| `allow_tagged` | map | empty | Tag to principal for tagged nodes. Keys must start with `tag:`. Values must not be empty. |
| `require_mapping` | bool | `true` | Reject logins that are not in `principal_map`. When `false`, an unmapped login acts as its own login name. |
| `allow_self` | bool | `false` | Accept requests from a tailnet IP of this node. |
| `forward_management` | bool | `false` | Forward management, plugin page, and OAuth callback paths. |
| `allowed_origins` | list | empty | Browser origins (`https://host` or `http://host:port`) that may call the proxy across origins. |
| `allowed_hosts` | list | empty | Extra `Host` names to accept, besides the node's IPs, short name, FQDN, and host name. |
| `log_requests` | bool | `false` | Log one line per request with the login and the masked principal. Also log denied requests. |

Default `state_dir`: `/root/.cli-proxy-api/tailscale` when `/root/.cli-proxy-api` exists (the CPA Docker image), else `~/.cli-proxy-api/tailscale`.

The plugin rejects a config with an invalid value: an unknown mode, a port out of range, a bad upstream URL, a bad tag, or an empty principal. CPA then logs the error.

Example:

```yaml
server:
  host: "127.0.0.1"
  port: 8317
  trusted-proxies: ["127.0.0.1", "::1"]  # needed only with forward_management

plugins:
  enabled: true
  dir: "plugins"
  configs:
    tailscale-identity:
      enabled: true
      mode: auto
      listen_port: 8318
      # embedded mode
      hostname: cliproxy
      state_dir: ""                      # default, see above
      auth_key: ""                       # or TS_AUTHKEY
      # identity
      principal_map:
        alice@github: sk-example-alice
        bob@example.com: sk-example-bob
      allow_tagged:
        tag:ci: ci-bot
      require_mapping: true
      # request policy
      allow_self: false
      forward_management: false
      allowed_origins: []
      allowed_hosts: []
      log_requests: false
```

### Principal rules

1. A tagged node gets the principal of its first tag, in sorted order, that is in `allow_tagged`. If no tag matches, the proxy answers 403. A tagged node never uses `principal_map`.
2. A user node gets `principal_map[login]`. If the login is not in the map, the proxy answers 403. With `require_mapping: false`, the node gets its login name as principal.
3. An address that is not a tailnet peer gets 403.

## Security model

- **Identity source.** The trust anchor is the WireGuard source address of the connection. WhoIs maps it to a user or a tagged node. A tailnet peer cannot fake its source address.
- **Secret header.** The proxy removes all identity headers that the client sends. This includes the `X-Forwarded-*` headers, `Forwarded`, and the `Tailscale-*` identity headers. It then sets its own values and the secret. The secret is 32 random bytes, new each time the library loads, and kept only in process memory. The plugin compares it in constant time. No status or management response contains it.
- **Direct access to CPA.** Bind CPA to loopback. In `system` and `embedded` mode, a caller who reaches CPA directly cannot set an identity without the secret. That caller can still use a built-in API key. In `headers` mode, loopback binding is mandatory.
- **Browsers.** A tailnet identity works like a cookie: the browser of a tailnet user carries it to any page. CPA answers every request with `Access-Control-Allow-Origin: *`. Without protection, a web page could call the proxy as that user. The proxy thus:
  - accepts only `Host` values that name this node (its tailnet IPs, short name, FQDN, host name) or are in `allowed_hosts`. This stops DNS rebinding.
  - rejects a request with a foreign `Origin` or with `Sec-Fetch-Site: cross-site`, unless the origin is in `allowed_origins`. Same-origin requests pass.
  - rejects `OPTIONS` without an `Origin`.
  - removes all `Access-Control-*` headers from CPA responses. It adds them back only for an origin in `allowed_origins`.
- **Self-access.** In `system` mode, a local process can connect to the host's own tailnet IP. That IP is then its source. WhoIs then returns the host node and its owner. Every local user, container, or browser page on the host would get the owner's principal without a key. The proxy rejects these requests unless `allow_self: true`.
- **API keys first.** CPA usually runs its built-in API key provider before plugins. A tailnet caller that also sends a valid API key gets that key as principal. An invalid key does not block the request: CPA then tries this plugin.
- **Management paths.** The proxy does not forward management, plugin page, and OAuth callback paths unless `forward_management: true`. See [Management over the tailnet](#management-over-the-tailnet).
- **Tagged nodes.** Tagged nodes have no user login. They get access only through an explicit `allow_tagged` entry.
- **Shared-in users.** Users of other tailnets can reach the node when you share it with them. WhoIs returns their own login. With `require_mapping: true` they need a mapping like any other user. With `require_mapping: false`, the Tailscale ACL and node sharing are the only access control.
- **Login URL.** Whoever opens the embedded login URL adds the node to their tailnet. The URL appears in the CPA log and in the status. Treat logs that hold it as sensitive. The status route needs the management key.
- **Principals in logs.** A principal is often a client API key. Request logs show only its first 6 and last 4 characters.
- **In-process code.** The plugin is a shared library in the CPA process with the same rights as CPA. Install it only from a source that you trust, and verify the checksum.

## Troubleshooting

### 403 responses

The body of a 403 from the proxy starts with `forbidden:`.

| Message | Cause | Fix |
|---|---|---|
| `host not allowed` | The `Host` header is not a name or IP of this node. | Use the MagicDNS name or the tailnet IP. For another name, add it to `allowed_hosts`. |
| `cross-origin request` | A browser sent an `Origin` of another site. | Add the origin to `allowed_origins` if you trust it. |
| `cross-site request` | A browser sent `Sec-Fetch-Site: cross-site` or `same-site`. | Add the origin to `allowed_origins` if you trust it. |
| `preflight request` | An `OPTIONS` request came without an `Origin`. | Send a normal request. |
| `request from this node itself (set allow_self to accept)` | The caller runs on the CPA host and used the tailnet IP. | Call CPA on `127.0.0.1:8317` with an API key, or set `allow_self: true`. |
| `management paths are not forwarded on the tailnet listener` | The path is a management, plugin page, or OAuth callback path. | Set `forward_management: true`. Read [Management over the tailnet](#management-over-the-tailnet) first. |
| `not a tailnet peer` | WhoIs does not know the source address. | Connect over the tailnet. |
| `login is not in principal_map` | The login has no mapping and `require_mapping` is `true`. | Add a mapping on the plugin page. |
| `tagged node has no tag in allow_tagged` | A tagged node has no tag in `allow_tagged`. | Add one of its tags to `allow_tagged`. |
| `peer has no tailnet user identity` | WhoIs returned no login. | Check the node in the Tailscale admin console. |

Other errors from the proxy:

- `503 tailnet identity lookup failed`: the WhoIs call failed or took more than 5 seconds. Check that tailscaled runs.
- `502 upstream unavailable`: the proxy cannot reach `upstream`. Check that CPA listens on that address.
- `401` from CPA: the request reached CPA but no provider authenticated it. In `headers` mode, check that `tailscale serve` sends `Tailscale-User-Login`.

### The status shows NeedsLogin

The embedded node is not logged in. Open the login URL from the status page or from the log. Or set `auth_key` or `client_secret`. The state stays in `state_dir`. If `state_dir` is not on a persistent volume, the node needs a new login after each container rebuild.

### auto mode stays in "waiting"

tailscaled answers, but it is not ready. `last_error` gives the reason:

- `tailscaled backend state is Stopped` or `NeedsLogin`: start or log in tailscaled on the host (`tailscale up`).
- `tailscaled has no tailnet IPs`: wait for tailscaled to connect.
- `cannot bind a tailnet IP on port ...`: another process uses the port. Or the port is below 1024, and CPA has no right to bind it. Change `listen_port`.
- `tailscaled LocalAPI did not answer: ...`: the socket exists, but the plugin cannot use it, for example "permission denied". Give CPA read access to the socket. `auto` does not switch to `embedded` in this case.

If you want a separate node and not the host's tailscaled, set `mode: embedded`.

### The plugin page says "refused to connect" in the management center

A build before v0.2.0 did not allow the page in a frame. Install v0.2.0 or later.

### CPA does not load a new plugin version

CPA loads a new library only when the selected file path changes and a config reload happens.

1. Give the new file a new versioned name, for example `tailscale-identity-v0.2.1.so`. CPA does not see a file that changes in place.
2. Change the config, for example save a setting in the management center. Or restart CPA.
3. If a `store.version` entry pins an older version, remove it or install the new version from the store.

The log line `pluginhost: plugin hot reloaded` confirms the swap.

### Config changes on the host do not reach the container

CPA writes `config.yaml` in place. Saves from the management center and the plugin page thus keep a single-file Docker bind mount intact. Many editors and `sed -i` replace the file with a new one. The container then still sees the old file until it restarts. To fix this, use one of these methods: restart the container after the edit, mount the directory that holds `config.yaml`, or use an editor that writes in place.

### 401 or 403 on management over the tailnet

- `401 invalid management key`: the local password works only from loopback. Use the key from `management.secret-key`. The browser also stores the remembered key per origin, so log in again on the tailnet origin.
- `403 remote management disabled`: set `management.allow-remote: true`. This applies only after you set `server.trusted-proxies`, because CPA then sees the real tailnet IP.
- `403 IP banned due to too many failed attempts`: wait 30 minutes or restart CPA.
- `403 forbidden: management paths are not forwarded...`: set `forward_management: true`.

## Limits

- **Hot reload.** A new plugin version retires the old library, but CPA cannot unload it. Go shared libraries do not unload. The plugin stops its listener and its tsnet node when CPA retires it. The Go runtime of the old copy stays in memory until the process exits.
- **Listener restart.** A change to a plugin setting restarts the listener. Open streams and WebSocket connections end.
- **Disable.** `plugins.configs.tailscale-identity.enabled: false` removes the plugin from the active set. CPA does not stop it, so the listener stays open until the next retire, unload, or process exit.
- **WhoIs per request.** Each request makes one LocalAPI WhoIs call. HTTP keep-alive reuses the connection, not the result.
- **TLS.** The first certificate fetch can take more than 10 seconds. A client that connects by IP sends no SNI, and the plugin then uses the first certificate domain. TLS mode is not yet tested end to end.
- **Embedded mode.** It runs a userspace network stack in the CPA process. Expect more memory use. tsnet also reads `TS_*` variables from the process environment. The plugin sets the fields it knows, but other tsnet settings still apply.
- **headers mode.** It cannot identify tagged nodes. It is not yet tested end to end.
- **Not yet tested.** A tailscaled restart while CPA runs, and a tailnet IP change.
- **Windows.** No build.

## Building and releasing

The module needs Go 1.26.6 (`tailscale.com` v1.102.5). With `GOTOOLCHAIN=auto`, an older Go downloads it. Linux builds need Docker.

```sh
make test                  # go test -race ./internal/...
make vet                   # go vet, with and without tsid_noembed
make build-darwin          # bin/darwin/<arch>/tailscale-identity-v<VERSION>.dylib
make build-darwin DARWIN_ARCH=amd64
make build-linux-amd64     # bin/linux/amd64/...so, built in golang:1.26-bookworm
make build-linux-arm64
make build-darwin TAGS=tsid_noembed   # system and headers mode only, smaller file
make dist                  # darwin (native arch) + linux/arm64, then package
make package               # zip every library in bin/ and write dist/checksums.txt
```

`VERSION` in the `Makefile` is the version source. It must be a dotted numeric version, for example `0.2.0`, without a leading `v`. The build writes it into the library and into the file name.

Approximate file sizes: 21 MB (darwin/arm64), 24 MB (linux/arm64). A `tsid_noembed` build is smaller because it has no tsnet.

### Release

1. Set `VERSION` in the `Makefile` and in `deploy/Dockerfile.example`.
2. Add a `## v<version> - <date>` section to `CHANGELOG.md`.
3. Push a tag `v<version>`.

The release workflow then:

1. checks that the tag is `v<dotted numeric>` and that `CHANGELOG.md` has a section for it.
2. runs `make vet test`.
3. builds linux/amd64 and linux/arm64 in `golang:1.26-bookworm`, and checks that no symbol needs a glibc newer than 2.36.
4. builds darwin/arm64 and darwin/amd64 on macOS and checks the architectures and the exported `cliproxy_plugin_init`.
5. packages the zips, verifies `checksums.txt`, and creates the GitHub release with the changelog section as release notes.

### Store asset format

The CPA plugin store expects these release assets:

- `tailscale-identity_<version>_<goos>_<goarch>.zip`, with exactly one library at the zip root, named `tailscale-identity.so` or `tailscale-identity.dylib`.
- `checksums.txt` in `sha256sum` format, with one line per zip.

`scripts/package.sh` makes both and checks the zip layout. `registry.json` is the store entry for this repository. It holds no version: the store reads the version from the GitHub release.

## License

MIT. See [LICENSE](LICENSE).
