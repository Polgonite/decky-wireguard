# Troubleshooting

This guide explains the status indicators, Smart connect waits, and diagnostic
logs. For profile fields and startup settings, see
[Configuration](configuration.md).

## Understand the status

| Status | Meaning |
| --- | --- |
| Gray / **Disconnected** | The profile is not active. |
| Gray / **Status unavailable** | The profile refresh failed. The panel reports the error; connection actions remain disabled until a successful refresh. |
| Gray / **Peer status unavailable** | The profile is active, but peer status or probing failed. The panel reports the error; connection actions, including Disconnect, remain available. |
| Yellow / **Verifying peer** | The tunnel is active, but the plugin has not yet observed fresh peer evidence. |
| Green / **Peer verified** | A peer completed a new handshake or sent newly received authenticated traffic during this activation. This does not guarantee ongoing peer health, internet access, or that all traffic is routed through the VPN. |
| Red / **No peer response** | No fresh peer evidence was observed within 30 seconds. This is not proof that the tunnel is broken. A late response can change it to green. |

Missing `wg`, permission failures, probe setup/send failures, and unreadable
peer data produce **Peer status unavailable** with an error rather than a red
timeout. If a connection action times out, refresh its status before retrying;
NetworkManager may still complete the action.

## Profile missing or unable to connect

- The plugin lists profiles managed by NetworkManager with the native
  WireGuard type. Profiles created only with `wg-quick` are not listed. Import
  the `.conf` file into the plugin editor or create/import the profile in
  NetworkManager.
- A new profile is saved disconnected and does not connect until you select
  **Connect** or configure a startup mode.
- Check that the profile has the right keys, tunnel addresses, peer AllowedIPs,
  and endpoint for your VPN. These values are not universally required by
  WireGuard, so the editor does not require every field.
- Profile settings determine routing, DNS, and any kill switch. The plugin does
  not provide a kill switch or change those policies.
- Multiple tunnels can remain active. Their routes may overlap or conflict;
  connecting one does not disconnect another.

The local configuration checks validate syntax and NetworkManager compatibility,
not whether the server has matching settings or is reachable.

## Smart connect does not activate

The management page shows the current wait condition for a pending profile:

- **Waiting for system boot to finish**: activation waits for systemd to report
  `running` or `degraded`.
- **Waiting for Steam login or Offline Mode**: check that Steam has completed
  login and initialized its services. Disable **Wait for Steam login** if this
  requirement is not appropriate.
- **Waiting for internet on a non-VPN connection**: NetworkManager must report
  `full` connectivity on a connected Wi-Fi, Ethernet, Bluetooth, or mobile-data
  device. Its connectivity check must be configured and enabled. Disable
  **Wait for internet** for private/offline-only VPNs.
- **Smart connect failed**: inspect the error in the panel. Readiness and
  activation failures are not retried automatically during that boot.
- **NetworkManager autoconnect is enabled**: an external change re-enabled
  autoconnect for this Smart connect profile. Select a startup mode again to
  resolve the conflict.

Smart connect is evaluated once per profile per boot. Restarting Decky or
reloading the plugin does not repeat the attempt. Enabling Smart connect after
the plugin's first load takes effect next boot. Manual Connect and Disconnect
cancel pending automatic activation for the current boot.

NetworkManager's normal connection-down behavior can temporarily inhibit
autoconnect until reboot or another explicit activation.

## No fresh peer response

Red means the plugin did not observe a fresh response, not necessarily that the
tunnel stopped passing traffic. Try reaching a service behind the tunnel before
switching modes or reconnecting. Check the peer endpoint and AllowedIPs, and
whether the network blocks the probe traffic. A listening peer can learn its
endpoint from authenticated incoming packets; a configured endpoint is not
always required for a listener.

The plugin binds probes to the WireGuard interface. It does not ping a public
endpoint or depend on a public service. A probe destination need not reply:
queuing traffic can prompt a handshake, and an established session can return
an authenticated WireGuard keepalive. Green records successful verification
for the current activation, not continuous health. Disconnecting or reconnecting
starts a new verification period.

## Diagnostic logging

To investigate a failure after sleep:

1. Open **Settings** from the connection list and enable **Diagnostic logging**.
2. Enable **Debug logging** for probe outcomes and peer samples.
3. Open the panel before sleeping and again immediately after waking. Peer
   samples are collected only while the panel is mounted, at most once every
   ten seconds per tunnel, with a fresh sample after a detected resume.
4. Note the `tunnel-N` reference shown at the bottom of the connection's
   management page and the affected peer aliases.
5. Collect the logs described below and note when status changed and whether
   traffic still worked.

Logs are in Decky's WireGuard plugin log directory (`DECKY_PLUGIN_LOG_DIR`,
normally under `~/homebrew/logs/`):

- `wireguard-diagnostics.log`
- `wireguard-diagnostics.log.1`, if present

Each file is capped at about 256 KiB. Diagnostics use local aliases such as
`tunnel-1-peer-2`, which are specific to one backend session. The files do not
include IP addresses, profile names, UUIDs, keys, or raw command output.
Disabling logging stops further recording but does not delete existing files.

Diagnostic logging records activation and verification changes, including
detected resumes. Debug logging adds probe outcomes, handshake ages, whether
receive/send counters changed, and whether a peer endpoint changed or was
missing. These settings persist across reloads.

Real Steam Deck and Decky integration must be checked on the device. See the
[development guide](development.md#testing) for automated test details.
