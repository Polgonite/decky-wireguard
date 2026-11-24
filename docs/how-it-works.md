# How it works

This document describes how the plugin integrates with NetworkManager, delays
startup, and decides whether a WireGuard peer has responded. For user-facing
symptoms and diagnostic steps, see
[Troubleshooting](troubleshooting.md).

## Components and profile changes

The Decky frontend lists NetworkManager profiles and sends actions to a Python
backend. The backend uses `nmcli` for profile listing, activation, autoconnect, and
advanced properties. It uses NetworkManager's D-Bus API directly to
read structured WireGuard settings, including peer data that SteamOS's `nmcli`
cannot edit. Settings writes use Python's standard-library D-Bus transport so
WireGuard keys do not appear in subprocess arguments.

The backend checks the system bus socket's Linux peer credentials before sending
settings. It accepts only root or the system D-Bus service account. Only
[listed non-secret properties](configuration.md#validation) can be passed as
arguments to `nmcli --offline`; WireGuard keys travel in the keyfile pipe.

The editor uses the system `libnm` to prepare the full draft before changing a
live profile. It retains unrelated settings from the original D-Bus profile.
The snapshot identifies the system bus instance, NetworkManager service owner,
profile object path, and version. Reading keys can advance that version, so the
editor watches for profile updates after the secret reply and records the
revision only if no intervening update occurred. It does not reread keys on
save. The backend holds only the latest editor snapshot, in memory for at most
30 minutes. If it expires, reload to keep non-conflicting edits. During a save,
owner lookup and write use the same authenticated connection. One `Update2` persists the result on that same object only
if its version still matches. It does not reapply the firewall zone or metered
setting to an active tunnel. New profiles use a single `AddConnection`. There is no
temporary live profile or rollback write. If the reply is lost, the backend
checks for matching, persisted settings at a stable revision. It treats known
NetworkManager defaults and equivalent DNS representations alike, but still
compares keys, secret-storage flags, and unrecognized settings. When it cannot
confirm the result it reports that uncertainty instead of overwriting potentially
newer settings.

The backend invokes system tools directly; it does not use a shell. Profile
operations are serialized and restricted to native NetworkManager WireGuard
profiles. NetworkManager settings determine routing and DNS; the plugin does
not provide a kill switch or disconnect other tunnels. Multiple active tunnels
can have overlapping routes.

## Smart connect lifecycle

At backend startup, the plugin records the Linux boot ID in its persistent
settings before attempting activation, even when no profiles are configured.
This prevents a backend or Decky restart from triggering another Smart connect
attempt during the same boot. Enabling Smart connect after that startup takes
effect on the next boot.

For each configured Smart connect profile, the backend waits until systemd
reports `running` or `degraded`, then checks its saved readiness requirements.
Steam readiness is reported by the frontend every two seconds using
`BHasCurrentUser()` and `GetServicesInitialized()`. The backend accepts reports
only while they are less than ten seconds old; missing APIs and errors are not
treated as ready.

Internet readiness requests a fresh NetworkManager connectivity check. It
requires `full` connectivity and a connected Wi-Fi, Ethernet, Bluetooth, GSM,
or CDMA device. VPN connectivity is not used as proof of internet access.
NetworkManager's connectivity check must be available and enabled; the plugin
does not choose or contact a separate internet-check endpoint.

The plugin reevaluates unmet requirements every five seconds. Once they are
met, it makes one bounded activation attempt per profile. An unmet requirement
is a waiting state; a readiness or activation error ends the attempt and is
reported in the panel. Profiles already connected or connecting are left
alone. External edits that re-enable NetworkManager autoconnect conflict with
Smart connect and cause the plugin to skip that profile. Manual Connect or
Disconnect cancels pending automatic activation for that profile for the
current boot.

## Peer verification

NetworkManager reports whether a profile is connected; it does not prove that
the remote peer is responding. While the panel is polling an active profile,
the backend reads `wg show <interface> latest-handshakes` and
`wg show <interface> transfer` to look for fresh evidence:

- A new handshake timestamp for any peer.
- An increase in a peer's received-byte counter. This includes authenticated
  WireGuard keepalives.

Sent bytes and successfully queued probes are not evidence of a response. For
a profile that was already active when tracking begins, existing handshake
timestamps and receive counters are baselines. A new handshake or receive
increase is required. The NetworkManager active-connection path identifies an
activation, so reconnecting starts a new verification period. Closing the panel
does not reset backend tracking.

Verification starts when the plugin requests activation or first observes an
external activation. If no fresh evidence appears within 30 seconds, the status
becomes **No peer response**. Verification continues after this timeout, so
later evidence can turn the status green.

## Probes and routing

To prompt a handshake when necessary, the plugin sends a small round of probes
while the active profile is unverified, then at most once every five seconds
while the panel is open. It continues probing after verification. When
verification succeeds, it sends one extra round immediately and then resumes
the interval.

For each peer, the plugin prefers a root DNS NS query to a DNS server covered
by that peer's AllowedIPs. It also tries an ICMP echo to a non-local address
inside a peer's AllowedIPs. IPv4 and IPv6 are supported. Probe sockets are
bound to the WireGuard interface, so they cannot fall back to Wi-Fi or another
tunnel.

No public service, public endpoint ping, or internet access is required. For a
default route without a known private target, an ICMP probe uses the
documentation-only address `192.0.2.1` or `2001:db8::1`; the address does not
need to reply. Queuing traffic can trigger a handshake, or an established
session can return an authenticated keepalive. There is no nondisruptive
command to force a new handshake on an already usable session.

The verification process does not change routes, keys, or keepalive settings.
The profile controls routes, DNS, AllowedIPs, and any kill-switch behavior.
Networks that block probes, missing endpoints, or unusable AllowedIPs can
prevent verification even if other tunnel traffic works.

## Status polling and peer details

The frontend refreshes status every second while a profile is connected or a
peer is being verified, and every five seconds otherwise while the panel is
mounted. A selected connected profile's endpoint IP, last-handshake age, and
cumulative received/sent counters refresh every five seconds. These counters
are historical interface totals; a recent handshake does not guarantee
ongoing peer health or protected routing. The status indicator ripples when a
probe is sent; the animation is disabled when reduced motion is requested.

When diagnostic logging is enabled, the backend writes anonymized activation
and verification events. Debug logging adds probe outcomes, handshake ages,
counter changes, and whether peer endpoint state changed. See
[Troubleshooting](troubleshooting.md#diagnostic-logging) for the log location,
rotation, and collection steps.
