# WireGuard for Decky

A Decky Loader plugin for listing, connecting, and disconnecting **existing
NetworkManager WireGuard profiles** from Steam Deck Gaming Mode.

## Requirements

- Steam Deck with Decky Loader (current stable, supporting `@decky/api` and API v1).
- NetworkManager running, with `nmcli` available to the Decky backend.
- At least one native NetworkManager WireGuard profile, with its keys already
  saved. Connections requiring an interactive password prompt are not supported.

Profiles created only with `wg-quick` are not shown. In Desktop Mode, import a
trusted configuration using NetworkManager's connection editor, or:

```sh
nmcli connection import type wireguard file /absolute/path/to/wg0.conf
```

Keep configuration files and private keys out of this repository. Importing may
enable NetworkManager autoconnect; review the imported profile's settings in
Desktop Mode before returning to Gaming Mode. The plugin does not change them.

## Build

Use Node.js 20+ with npm and Python 3.10+:

```sh
npm ci
npm test
npm run package
```

The installable archive is `out/decky-wireguard-0.1.0.zip`. Its single top-level
`decky-wireguard` directory contains the backend, plugin metadata, and compiled
`dist/index.js`. No Python packages or runtime npm installation are needed.

For frontend development, use `npm run watch`; `npm run typecheck` checks the UI.
The build uses Decky's official Rollup tooling and externalizes React and
`@decky/ui`, provided by the loader. TypeScript is pinned to 5.9 because the
current Decky Rollup plugin requires its JavaScript compiler API, which is not
available in TypeScript 7.

The official build tooling currently has transitive npm advisories in its
development dependencies, including `glob`, `minimatch`, and `deepmerge`.
These packages are not shipped in the plugin archive; avoid building untrusted
source trees. `npm audit --omit=dev` reports no runtime dependency advisories
for the committed lockfile at creation time.

## Install on Steam Deck

1. Enable Developer Mode in Decky Loader settings.
2. Use Decky's **Install Plugin from ZIP File** developer option and select the
   generated archive copied to your Deck. Approve installation only if you trust
   the code: the backend requests root privileges to control NetworkManager.
3. Open **WireGuard** in the Decky quick-access panel.

Do not install the source directory without building it first. If your Decky
version does not offer ZIP installation, extract the archive so the plugin is
at `~/homebrew/plugins/decky-wireguard/` (or your Decky's configured plugins
directory), then restart Decky Loader.

## Behavior and limitations

- Every native WireGuard profile is listed, including disconnected profiles.
  Names with colons and backslashes are supported, and actions use UUIDs so
  duplicate names are safe. The short UUID appears beside each status.
- Status refreshes every five seconds while the panel is mounted. Refresh also
  runs after each action. Unavailable status disables actions until a successful
  refresh, rather than treating an error as a disconnected profile.
- All mutations are serialized and restricted to WireGuard profiles. No shell is
  used. Missing tools, authorization failures, and NetworkManager errors appear
  in the panel. Actions have a 30-second NetworkManager wait limit; if an action
  times out, refresh before retrying because NetworkManager may still complete it.
- **Connected** means NetworkManager activated the interface, not that a
  WireGuard peer completed a handshake or that traffic is protected. Routing,
  DNS, allowed IPs, and kill-switch behavior belong to the imported profile.
- Multiple tunnels can be active. Connecting one does not disconnect others;
  overlapping routes may conflict.
- The plugin does not import, edit, delete, or display configuration secrets. It
  does not alter saved autoconnect settings, though NetworkManager's normal
  connection-down behavior can temporarily inhibit autoconnect until reboot or
  another explicit activation. Unloading the plugin leaves tunnels as they are.

Backend tests mock `nmcli`; they do not activate any host network connections.
Real Steam Deck/Decky integration must be checked on the device.
