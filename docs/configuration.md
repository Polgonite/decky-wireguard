# Configuration

This guide covers creating and editing NetworkManager WireGuard profiles in
Decky. For status explanations and failure diagnosis, see
[Troubleshooting](troubleshooting.md).

## Requirements and profile scope

The plugin lists native NetworkManager WireGuard profiles, including
disconnected profiles. It does not show profiles managed only by `wg-quick`.
Profile editing requires NetworkManager 1.44 or newer, its matching `nmcli` and
`libnm`. Smart connect's internet check also uses systemd's `busctl`.
Peer status and probing require `wg` from `wireguard-tools`.

The plugin does not support connections that require interactive password
prompts. Keys must be saved in the NetworkManager profile. The backend runs with
root privileges to manage profiles; install only trusted plugin builds.

## Add or edit a profile

Select **Add connection** to open the editor for a new profile, or **Edit
configuration** on a connection to edit it. A new profile receives a generated NetworkManager interface name, starts
disconnected, and has automatic startup disabled. Its display name can contain
spaces and Unicode.

The editor has **Interface** fields for the private key, addresses, and DNS,
followed by editable **Peer** sections. A peer needs a unique public key; peers,
addresses, DNS, Allowed IPs, endpoints, preshared keys, and keepalive are
otherwise optional. A normal client still needs suitable tunnel addresses,
Allowed IPs, and an endpoint to initiate traffic. A profile without peers cannot
exchange peer traffic, and a peer without Allowed IPs cannot carry IP traffic.
A listening peer can learn its endpoint from authenticated incoming packets.

Peer options not shown by the editor are preserved when an existing peer is
saved. Profile changes take effect the next time the tunnel connects; saving
does not itself connect or disconnect it. Leaving with unsaved edits asks for
confirmation. Back is unavailable while saving or reloading a saved profile.
If a save succeeds but reloading fails, the editor keeps the draft visible.
Select **Retry reload** to read the saved profile before editing again; this
does not repeat the write. If another editor changes the profile, choose
**Reload and keep my edits** to combine changes to different fields. If both
copies changed the same field (including the peer list) differently, the draft
is kept and nothing is written. Address edits also conflict with an external
IP method change if saving would overwrite that method. A peer already saved
with equivalent settings does not conflict, even if Allowed IPs or keepalive
have been normalized. **Discard edits and reload** asks for
confirmation.
If a save
times out, check the profile in the connection list before retrying: the
complete change may already have reached disk. Retrying the same new draft
reuses its UUID instead of creating a second profile. If the existing profile
cannot be verified as an exact match, **Open existing profile** lets you
inspect it after confirming that you want to discard the draft.

## Import a `.conf` file

Select **Import .conf file** in the editor. Import only fills the draft; select
**Save** to create or update the NetworkManager profile. If the name is blank,
the filename (without `.conf`) becomes the name.

Import replaces the private key, addresses, DNS, and entire peer list. Values
omitted from the file are cleared in those fields, including preshared keys.
The profile name and omitted advanced settings (including MTU, listen port,
firewall mark, and other NetworkManager properties) are retained. Fields present
in the file override the draft.

The importer accepts `[Interface]` `PrivateKey`, `Address`, `DNS`, `MTU`,
`ListenPort`, and `FwMark`, as well as the standard `[Peer]` fields `PublicKey`,
`PresharedKey`, `AllowedIPs`, `Endpoint`, and `PersistentKeepalive`. It rejects
unsupported directives such as `Table` and `PostUp`, malformed input, and
duplicate single-value fields without changing the draft. Files must be regular
UTF-8 `.conf` files no larger than 1 MiB and readable by the Decky desktop
user. Import uses `/usr/bin/python3` as that user, not root.

You can also import in NetworkManager's Desktop Mode editor or with:

```sh
nmcli connection import type wireguard file /absolute/path/to/wg0.conf
```

Desktop Mode imports may enable NetworkManager autoconnect. Review their startup
settings before rebooting. Keep configuration files and private keys out of
this repository.

## Validation

The editor validates the full draft, including unchanged and imported fields,
before saving. Errors identify the affected field without echoing private or
preshared keys.

| Field | Accepted values |
| --- | --- |
| Private, public, and preshared keys | Canonical base64 for exactly 32 bytes (44 characters ending in `=`). Private keys and each peer's public key are required; preshared keys are optional. |
| Addresses | IPv4 or IPv6 with an optional CIDR prefix (`0-32` or `0-128`). Bare addresses use `/32` or `/128`. Zone IDs such as `%eth0` are rejected. |
| Allowed IPs | IPv4/IPv6 addresses or networks, including `0.0.0.0/0` and `::/0`. Host bits are normalized to the network; zone IDs are rejected. |
| Endpoint | `hostname:port`, `IPv4:port`, or `[IPv6]:port`; decimal port from `1` to `65535`. |
| Listen port | Decimal integer from `0` to `65535`; empty or `0` selects one automatically. |
| Persistent keepalive | Decimal integer from `0` to `65535` seconds; empty, `0`, or `off` disables it. |
| MTU | Unsigned 32-bit decimal integer (`0-4294967295`); empty or `0` uses the default. Kernel and IP version affect usable values. |
| DNS | IPv4/IPv6 server IPs and search domains. `~domain` is a routing domain and `~.` routes all DNS. Existing `dns-data` profiles also support `IP#TLS-server-name`. |
| Firewall mark | Unsigned 32-bit decimal or `0x` hexadecimal; empty, `0`, or `off` disables it. |
| Interface name | 1-15 UTF-8 bytes; not `.` or `..`; no whitespace, `/`, `:`, or NUL. |

Separate lists with commas or whitespace. The plugin generates an interface
name for new profiles. It validates existing interface names and selected
NetworkManager IP settings before applying advanced edits.

For native WireGuard, IPv4 methods are limited to `manual` or `disabled`; IPv6
also permits `ignore` and `link-local`. `manual` requires at least one address
of that family. Methods without static addressing cannot be combined with
static addresses or DNS/search domains. DHCP/`auto` and `shared` are not
supported. UUID, connection type, and `connection.autoconnect` are managed
outside the raw advanced-property editor; use the startup controls for
autoconnect. **Add property** accepts only the following full property names;
other stored settings are left alone. Use NetworkManager's editor for unlisted
properties. Do not enter credentials in these fields.

| Setting | Editable properties |
| --- | --- |
| `connection` | `interface-name`, `zone`, `metered`, `autoconnect-priority` |
| `wireguard` | `fwmark`, `peer-routes`, `ip4-auto-default-route`, `ip6-auto-default-route` |
| `ipv4` and `ipv6` | `method`, `gateway`, `routes`, `routing-rules`, `route-table`, `route-metric`, `never-default`, `dns-priority`, `dns-options`, `ignore-auto-dns`, `ignore-auto-routes`, `may-fail` |
| `ipv6` only | `addr-gen-mode`, `ip6-privacy` |

For example, use `ipv4.dns-priority`. NetworkManager validates the completed
profile, so related changes such as clearing the last address and its gateway
can be saved together. A gateway cannot be combined with `never-default=yes`
for the same IP family. If an edit would implicitly change another routing
property, the editor rejects it; change both properties explicitly instead.
NetworkManager discards `may-fail=no` when the IP method is `disabled` or
`ignore`, so the editor rejects that combination.

These are local compatibility checks, not a connectivity test. They cannot
verify that the remote peer has matching keys, accepts the chosen addresses, or
is reachable.

## Startup options

Each connection has two mutually exclusive startup modes:

- **Connect during boot** enables NetworkManager's `connection.autoconnect`.
- **Smart connect** disables NetworkManager autoconnect and lets the plugin
  start the profile after systemd reports that boot is `running` or `degraded`.

Neither mode is required. Changing a mode does not immediately connect or
disconnect the profile. The plugin attempts Smart connect once per profile per
boot; profiles already connected or connecting are left alone. Because the VPN
is not active yet, normal network traffic may use the non-VPN connection before
Smart connect activates it. Smart connect is not a kill switch.

With **Show advanced settings** enabled in **Settings**, Smart connect exposes
two independent wait options:

- **Wait for Steam login** requires Steam's login services to be ready and
  includes a completed Offline Mode login.
- **Wait for internet** requires NetworkManager to report `full` connectivity
  on a connected Wi-Fi, Ethernet, Bluetooth, or mobile-data device. The
  NetworkManager connectivity check must be configured and enabled; VPN
  connectivity, Wi-Fi association alone, captive portals, and limited
  connectivity do not qualify.

Both wait options default to enabled, including for profiles configured before
the options existed. They are saved per profile and retained when Smart
connect or the advanced settings display is turned off. They do not affect
NetworkManager boot autoconnect or manual Connect actions. Turn off the internet
requirement for private or offline-only VPNs.

When a requirement is unmet, the management page shows what Smart connect is
waiting for and checks again every five seconds. Activation or readiness-check
errors are shown in the panel without automatic retries. A manual Connect or
Disconnect cancels that profile's pending automatic activation for the current
boot. If an external NetworkManager edit re-enables autoconnect for a Smart
connect profile, the plugin skips it and reports the conflict.

For the boot lifecycle, Steam heartbeat, and exact readiness checks, see
[How it works](how-it-works.md).

## References

- [WireGuard configuration format (`wg(8)`)](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8)
- [NetworkManager WireGuard settings](https://www.networkmanager.dev/docs/api/latest/settings-wireguard.html)
- [NetworkManager IPv4 settings](https://www.networkmanager.dev/docs/api/latest/settings-ipv4.html)
- [NetworkManager WireGuard verifier](https://github.com/NetworkManager/NetworkManager/blob/main/src/libnm-core-impl/nm-setting-wireguard.c)
