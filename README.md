# WireGuard for Decky

A Decky Loader plugin for creating, configuring, connecting, and disconnecting
**NetworkManager WireGuard profiles** from Steam Deck Gaming Mode.

## Requirements

- Steam Deck with Decky Loader (current stable, supporting `@decky/api` and API v1).
- NetworkManager running, with `nmcli` available to the Decky backend.
- `systemctl` and `busctl` from systemd for startup readiness and the configuration editor.
  The internet readiness option requires NetworkManager's connectivity check
  to be configured and enabled.
- `wg` from `wireguard-tools` available to the backend for handshake status.
- Connections requiring an interactive password prompt are not supported;
  keys must be saved in the profile.

Profiles created only with `wg-quick` are not shown. Select **Add connection**
to open the same editor used by **Edit configuration**.
Enter a name and configuration manually, or select **Import .conf file** to
browse for a trusted WireGuard configuration. A new connection uses the filename
as its name if no name has been entered. New profiles are created disconnected,
with automatic startup disabled.

Import only fills the editor: **Save** is required to create or update
the NetworkManager profile. Import replaces the private key, addresses, DNS and
entire peer list, clearing omitted values (including preshared keys). The name
and omitted advanced settings, including MTU, listen port, firewall mark and
other NetworkManager properties, are preserved. Values present in the file
override their fields. The importer supports `[Interface]` PrivateKey, Address,
DNS, MTU, ListenPort and FwMark, plus all standard `[Peer]` fields. Unsupported
directives (such as wg-quick hooks or Table), malformed files and duplicate
single-value fields are rejected without changing the draft. Files must be
UTF-8 and at most 1 MiB.

Alternatively, import using NetworkManager's Desktop Mode editor, or:

```sh
nmcli connection import type wireguard file /absolute/path/to/wg0.conf
```

Keep configuration files and private keys out of this repository. Desktop Mode
imports may enable NetworkManager autoconnect; review the imported profile's settings in
Desktop Mode or use the plugin's startup checkboxes before rebooting.

Closing the full-screen configuration editor reopens the WireGuard plugin panel
with the edited connection selected. If that connection is no longer available,
the panel returns to the connection list. Unsaved edits require confirmation
before they are discarded. Back/B is unavailable while saving and reloading the
saved configuration.

## Configuration validation

Saving a new or existing profile validates the entire configuration, including
unchanged fields and imported values, before writing it. A failure leaves the
draft available for correction and reports the affected field without echoing
private or preshared keys.

The minimum user-entered settings are a **nonempty name and private key**.
Every peer you add also needs its own **public key**, unique within the profile.
NetworkManager additionally requires a valid device interface name; the plugin
generates one for new connections. The display name is not an interface name:
it can contain spaces and Unicode.

| Field | Accepted format |
| --- | --- |
| Private/public/preshared keys | Canonical base64 encoding of exactly 32 bytes: 44 characters ending in `=`. Private keys and each peer's public key are required; preshared keys are optional. |
| Address | IPv4 or IPv6, optionally with a CIDR prefix (`0-32` or `0-128`). Bare addresses use `/32` or `/128`. No `%interface` zone IDs. |
| Allowed IPs | IPv4/IPv6 addresses or CIDR networks, including `0.0.0.0/0` and `::/0`. Host bits are normalized to the network. No zone IDs. |
| Endpoint | `hostname:port`, `IPv4:port`, or `[IPv6]:port`; decimal port `1-65535`. |
| Listen port | Decimal integer `0-65535`; empty or `0` chooses automatically. |
| Persistent keepalive | Decimal integer `0-65535` seconds; empty, `0`, or `off` disables it. |
| MTU | Unsigned 32-bit decimal integer (`0-4294967295`); empty or `0` uses the default. Actual usable MTUs also depend on the kernel and IP version. |
| DNS | IPv4/IPv6 server IPs and search domains; `~domain` is a routing domain and `~.` routes all DNS. Existing `dns-data` profiles also support `IP#TLS-server-name`. |
| Firewall mark | Unsigned 32-bit decimal or `0x` hexadecimal; empty, `0`, or `off` disables it. |
| Advanced interface name | `1-15` UTF-8 bytes, not `.` or `..`, with no whitespace, `/`, `:`, or NUL characters. |

Separate lists with commas or whitespace. Addresses, DNS, peers, Allowed IPs,
endpoints, preshared keys, and keepalive are not universally required by
WireGuard, so they are not made mandatory. A normal VPN client still needs
appropriate tunnel addresses, peer Allowed IPs, and an endpoint to initiate
traffic. A profile without peers cannot exchange peer traffic; a peer without
Allowed IPs cannot carry IP traffic. A listening peer can learn its endpoint
from authenticated incoming packets.

For native WireGuard, IPv4 methods are limited to `manual` or `disabled`; IPv6
also permits `ignore` and `link-local`. `manual` requires at least one address
of that family. Methods without static addressing cannot be combined with
static addresses or DNS/search domains. DHCP/`auto` and `shared` are not
supported. These combinations and interface names are checked before applying
advanced edits. UUID and connection type are managed by NetworkManager and
cannot be edited here; startup controls still own autoconnect.
Use full property names for checked settings; shorthand names are rejected so
they cannot bypass these checks.

These are local compatibility checks, not a connectivity test: they cannot
verify that the remote peer has matching keys, accepts the chosen addresses,
or is reachable. Other advanced property values are still validated by
NetworkManager itself.

Sources: [WireGuard's configuration format (`wg(8)`)](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8),
[NetworkManager WireGuard settings](https://www.networkmanager.dev/docs/api/latest/settings-wireguard.html),
[NetworkManager IPv4 settings](https://www.networkmanager.dev/docs/api/latest/settings-ipv4.html),
and [NetworkManager's WireGuard verifier](https://github.com/NetworkManager/NetworkManager/blob/main/src/libnm-core-impl/nm-setting-wireguard.c).

## Build

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) and Git.
uv downloads Python 3.13 and installs the pinned Node.js 22/npm and development
tools in the repository's `.venv`; no system Node.js installation is needed:

```sh
uv sync --locked
uv run --locked npm ci
uv run --locked npm test
uv run --locked npm run package
```

The installable archive is `out/decky-wireguard-0.1.0.zip`. Its single top-level
`decky-wireguard` directory contains the backend, plugin metadata, and compiled
`dist/index.js`. No Python packages or runtime npm installation are needed.

For frontend development, use `uv run --locked npm run watch`;
`uv run --locked npm run typecheck` checks the UI.
The build uses Decky's official Rollup tooling and externalizes React and
`@decky/ui`, provided by the loader. TypeScript is pinned to 5.9 because the
current Decky Rollup plugin requires its JavaScript compiler API, which is not
available in TypeScript 7.

The official build tooling currently has transitive npm advisories in its
development dependencies, including `glob`, `minimatch`, and `deepmerge`.
These packages are not shipped in the plugin archive; avoid building untrusted
source trees. `npm audit --omit=dev` reports no runtime dependency advisories
for the committed lockfile at creation time.

## Development releases

Every push to `main` runs `.github/workflows/development-release.yml`, which
tests the backend, type-checks and builds the frontend, verifies the ZIP, then
publishes it on the [GitHub Releases page](https://github.com/Polgonite/decky-wireguard/releases).
All releases are marked **prerelease**, not stable or latest.

Both CI jobs use Ubuntu 24.04 runners to avoid automatic OS migrations.
The checkout and setup actions use Node.js 24 internally; the project still
builds with Node.js 22.

Each build gets a version such as `0.1.0-dev.123456789.1.shaabcdef0`, containing
the workflow run ID, attempt number, and short commit SHA. Reruns create distinct
releases instead of overwriting previous assets. That version is embedded in the
packaged `package.json` and ZIP filename; source versions are not committed back.
Releases target the exact pushed commit. The pre-commit checks job uses the same
locked uv environment as local development. It is currently disabled because
checks run locally before pushing. To enforce checks on pull requests and pushes
and block publication on failure, remove its `if: ${{ false }}` and uncomment
`needs: checks` on the release job.
Runs are not canceled or grouped by a
concurrency limit, so each push can publish its own build after successful checks.

The workflow uses the automatic `GITHUB_TOKEN` with `contents: write`; no
additional secret is required. Repository or organization policies must allow
GitHub Actions to create releases.

## Development environment and pre-commit

From the repository root, create the uv venv, install npm dependencies, and
install the Git pre-commit hook:

```sh
uv sync --locked
uv run --locked npm ci
uv run --locked pre-commit install
uv run --locked pre-commit run --all-files
uv run --locked npm run package
```

The hooks lint Python with Ruff, lint JavaScript/TypeScript with ESLint, check
frontend types, run backend tests, and validate Actions workflows (including
embedded shell) with actionlint/ShellCheck. Python is selected by
`.python-version`; `pyproject.toml` pins Node.js, pre-commit, Ruff, actionlint, and
ShellCheck, and `uv.lock` locks their dependencies. Node.js, actionlint, and
ShellCheck are supplied through Python wrapper packages. Local and CI commands
use `--locked` so dependency changes require an explicit `uv lock`.

The hooks invoke tools through `uv run --locked`, so they work without activating
the venv, provided uv and Git are on your `PATH`. For an interactive shell with
plain `npm`, `python3`, and `pre-commit` commands, activate it:

```sh
source .venv/bin/activate
```

VS Code retains the ESLint and Ruff extension recommendations in
`.vscode/extensions.json`. Launch it from the activated shell so extensions can
find the venv's Node.js and Python tools.

### Committing from the terminal

After the setup above, run these commands from the repository root:

```sh
git status --short
git diff
git add README.md src/index.tsx # Replace with the files you intend to commit.
git diff --cached --check
git diff --cached
```

Commit normally; the installed hook uses the uv environment and your existing
Git identity:

```sh
git commit -m "Describe the change"
git status --short
git --no-pager log --oneline -1
```

If Git cannot resolve your identity, configure it first. If a hook
fails, fix the reported issue and retry without bypassing hooks. If a hook
rewrites files, review and stage those changes before retrying. An empty final
status means the working tree is clean.

## Install on Steam Deck

1. Enable Developer Mode in Decky Loader settings.
2. Use Decky's **Install Plugin from ZIP File** developer option and select the
   downloaded development release ZIP or generated archive copied to your Deck.
   Approve installation only if you trust
   the code: the backend requests root privileges to control NetworkManager.
3. Open **WireGuard** in the Decky quick-access panel.

For subsequent updates, open **Settings** from the connection list, select
**Update to latest build**, then approve Decky's installation dialog. The button
checks the repository's 100 most recent GitHub releases, including development prereleases, and selects
the most recently published installable ZIP. It shows the installed version and
does not reinstall the same version. GitHub's SHA-256 asset digest is required
and passed to Decky for verification. Decky downloads, installs, and reloads the
plugin; NetworkManager profiles and persistent startup settings are not changed.
An internet connection is required; API limits, missing digests, and download
errors are reported instead of falling back to an older build. Installation
progress and installation errors appear in Decky's dialog. This uses Decky's
internal native installer because `@decky/api` has no public installation API;
if unavailable, update Decky Loader or install the release ZIP manually.

Do not install the source directory without building it first. If your Decky
version does not offer ZIP installation, extract the archive so the plugin is
at `~/homebrew/plugins/decky-wireguard/` (or your Decky's configured plugins
directory), then restart Decky Loader.

## Behavior and limitations

- Every native WireGuard profile is listed, including disconnected profiles.
  Names with colons and backslashes are supported, and actions use UUIDs so
  duplicate names are safe. Select a connection to open its management menu and
  connect or disconnect it; press B or select Back to return to the list without
  closing the sidebar. B on the connection list returns to Decky's plugin list,
  including while profiles are loading or when no profiles are available.
  The short UUID appears beside each status. **Settings** opens the logging and
  update controls; press B or select Back to return to the connection list.
- Select **Edit configuration** to open a full-screen editor that lays out the
  profile like a WireGuard `.conf` file: **Interface** (private key with its derived public key, addresses,
  DNS servers and search domains) followed by each **Peer** (public key, preshared
  key, allowed IPs, endpoint, persistent keepalive). Peers can be added and
  removed. **Show advanced**, above Save, reveals listen port, MTU, and the
  remaining raw NetworkManager properties, including adding one; hiding them
  preserves any edits. Interface and peer fields are read and saved through
  NetworkManager's D-Bus API with `busctl`, because SteamOS's `nmcli` cannot edit
  WireGuard peers; peer options this editor does not show are preserved.
  Automatic connection is managed separately by the mutually exclusive startup
  controls. The editor displays secret values; changes are validated before
  anything is saved and take effect the next time the tunnel connects. Leaving
  the editor with Back or the B button asks before discarding unsaved changes.
- Every connection management page has two mutually exclusive startup checkboxes.
  **Connect during boot** sets NetworkManager's `connection.autoconnect` through
  `nmcli`; this can delay boot when the Deck is offline. **Connect after boot**
  disables NetworkManager autoconnect and lets the backend attempt activation
  when the plugin loads, after systemd reports boot finished (`running` or
  `degraded`). Neither checkbox needs to be enabled; changing them does not
  immediately connect or disconnect the tunnel.
- Two independent per-connection checkboxes control plugin-managed startup:
  **Wait for Steam login** and **Wait for internet**. Both default to enabled,
  including for connections configured before these options were added. They
  only appear when **Connect after boot** is enabled, and their saved values
  are preserved when it is turned off and on again. They do not affect
  NetworkManager boot autoconnect or manual Connect actions.
  Turn off the internet requirement for private/offline-only VPNs if needed.
- Steam readiness is monitored from plugin initialization, even with the panel
  closed. It uses Steam's `BHasCurrentUser()` login-completion predicate and
  `GetServicesInitialized()`, including a completed Offline Mode login, without
  assuming a numeric value for Steam's internal login-state enum. The UI
  reports readiness every two seconds; unavailable APIs, errors, or a report
  older than ten seconds never count as ready.
- Internet readiness requests a fresh NetworkManager connectivity check and
  requires `full` connectivity on a connected Wi-Fi, Ethernet, or mobile-data
  device. A VPN's connectivity, Wi-Fi association alone, captive portals, and
  limited connectivity do not qualify. This uses NetworkManager's configured
  connectivity-check service, not a plugin-selected endpoint. Disabled or
  unconfigured checks produce an actionable error and leave the VPN off,
  rather than trusting a default route as proof of internet access.
- With either requirement unmet, the backend leaves the tunnel off and checks
  again every five seconds. Each connection waits independently; its management
  page shows what it is waiting for. Requirement changes apply to pending
  startup work. Manual Connect or Disconnect cancels that connection's pending
  automatic activation for this boot, even if it is already disconnected.
- After-boot preferences and the last handled Linux boot ID are saved atomically
  in Decky's persistent plugin settings directory (`startup.json`). The backend
  records the boot before attempting activation, including when no profiles are
  configured. Closing the panel, reloading the frontend, restarting Decky, or
  reloading the backend does not trigger another attempt during the same boot.
  Enabling this option after the plugin's first load takes effect next boot.
  Uninstalling or deleting plugin settings resets this record.
- After-boot activation runs in the background without blocking plugin loading
  or the system boot path. After its enabled requirements are met, each configured
  tunnel gets one bounded activation attempt; activation/readiness-check errors
  are shown in the panel with no automatic retries. Missing internet or an
  unfinished Steam login is a waiting condition, not an activation failure.
  Already active or activating tunnels
  are left alone. Unloading cancels pending startup work; it does not retry on
  reload that boot. External NetworkManager edits that re-enable autoconnect
  cause the plugin to skip that tunnel and report the conflict.
- Status refreshes every second while verifying a peer, otherwise every five
  seconds while the panel is mounted. Refresh also
  runs after each action. Refreshes keep the current controls visible and only
  update profiles when the response changes; connection actions still show a
  busy state. Unavailable status disables actions until a successful refresh,
  rather than treating an error as a disconnected profile.
- A selected connected profile shows per-peer last-handshake age and cumulative
  received/sent traffic counters, refreshed every five seconds. Public keys are
  abbreviated. These are historical diagnostics: traffic totals are interface
  counters, and a recent handshake does not guarantee ongoing peer health.
- All mutations are serialized and restricted to WireGuard profiles. No shell is
  used. Missing tools, authorization failures, and NetworkManager errors appear
  in the panel. Actions have a 30-second NetworkManager wait limit; if an action
  times out, refresh before retrying because NetworkManager may still complete it.
- The status circle is **gray** when deactivated, **gently pulsing yellow**
  while verifying a peer, **green** once any peer completes a new handshake or
  sends newly received authenticated traffic, and **red** if neither is observed
  within 30 seconds. A late response changes red to green. Green stays until
  deactivation; it does not indicate ongoing peer health, internet access, or protected routing.
  Pulsing is disabled when reduced motion is requested.
- Evidence is read with `wg show <interface> latest-handshakes` and
  `wg show <interface> transfer`, without reading private keys. An increase in
  a peer's receive counter includes authenticated WireGuard keepalives; sent
  bytes and successful probe sends are never counted as proof of connectivity.
  Each NetworkManager active-connection path identifies
  an activation, so reconnecting resets status even between refreshes. The
  timeout starts when the plugin requests activation, or first observes an
  external activation. For tunnels already active when the backend starts,
  existing handshake timestamps and received byte counts are baselines: a new
  handshake or newly received authenticated traffic is required.
  Closing and reopening the panel does not reset backend tracking.
- While unverified, the plugin sends a small round of probes immediately and
  at most once every 10 seconds while the panel is open. It prefers a root NS
  query to the tunnel's configured DNS server when covered by that peer's
  AllowedIPs, and also sends an ICMP echo to a non-local address in its allowed
  ranges. Both IPv4 and IPv6 are supported. Sockets are bound to the WireGuard
  interface: probes must not fall back to Wi-Fi or another tunnel.
- No fixed public service, public endpoint ping, or internet access is required.
  For default routes without a known private target, an ICMP probe uses a
  documentation-only address (`192.0.2.1` or `2001:db8::1`); it need not reply.
  Queuing traffic triggers a handshake when necessary, and an established
  session can instead return an authenticated WireGuard keepalive. DNS/ICMP
  replies can verify faster, but a reply from the probe destination itself
  is not required. There is no nondisruptive command to force a new handshake
  on an already usable session.
- No routes, keys, or keepalive settings are changed. This
  works at the WireGuard protocol level rather than relying on a particular
  provider or assuming the server's tunnel address is `.1`. Networks blocking
  probes, missing endpoints, or unusable AllowedIPs can prevent verification;
  red means no fresh evidence, not definitive proof the tunnel is broken.
  Missing `wg`, permission failures, probe setup/send failures, and unreadable
  data produce gray/unavailable status with an error, not a red timeout, and do not prevent
  disconnecting. Routing, DNS, allowed IPs, and kill-switch behavior belong to
  the imported profile.
- Multiple tunnels can be active. Connecting one does not disconnect others;
  overlapping routes may conflict.
- The plugin does not import or delete profiles. Secrets are shown only in the
  configuration editor, and profiles change only through that editor or the startup
  autoconnect setting. NetworkManager's normal
  connection-down behavior can temporarily inhibit autoconnect until reboot or
  another explicit activation. Unloading the plugin leaves tunnels as they are.

### Diagnosing a failure after sleep

Red means the plugin did not observe a fresh peer response, not necessarily
that the tunnel stopped passing traffic. A tunnel that stayed green may simply
have been verified before sleep. If it happens again, try reaching a service
behind the affected tunnel before switching modes or reconnecting.

Open **Settings** from the connections list and turn on **Diagnostic logging** for
NetworkManager activation and verification changes, including detected resumes.
Then turn on **Debug logging** for probe outcomes, handshake ages, whether
receive/send counters changed, and whether a peer's endpoint changed or was
missing. These settings persist across reloads. Open the panel before sleeping
and again right after waking: peer samples are taken only while it is open,
at most every 10 seconds per tunnel, with a fresh sample after a detected resume.

Collect `wireguard-diagnostics.log` and, if present, `wireguard-diagnostics.log.1`
from Decky's WireGuard plugin log directory (`DECKY_PLUGIN_LOG_DIR`, normally
under `~/homebrew/logs/`). The two files are capped at about 256 KiB each.
Note the affected `tunnel-N` shown in the plugin, when it went red, and whether
traffic still worked. Aliases such as `tunnel-1-peer-2` are local to one backend
session. The log does not include IP addresses, names, UUIDs, keys, or raw
command output. Disabling logging also disables debug and stops recording
without deleting the existing files.

Backend tests mock `nmcli`, `busctl`, and `wg`; they do not activate any host network connections.
`npm test` also exercises the frontend readiness monitor with mocked Steam APIs,
including online/offline login, unfinished initialization, API errors, and unloading.
Real Steam Deck/Decky integration must be checked on the device.
