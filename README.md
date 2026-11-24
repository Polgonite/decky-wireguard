# WireGuard for Decky

Manage NetworkManager WireGuard VPN connections from Steam Deck Gaming Mode.
View existing profiles, add or edit profiles, import a WireGuard configuration,
and connect or disconnect tunnels without leaving the Decky quick-access panel.

The plugin can also connect profiles during boot or wait for Steam login and
internet readiness before connecting. Smart connect may allow normal network
traffic before it connects. Peer status and traffic details help diagnose a
connection, but a verified peer does not guarantee that all traffic is using
the VPN.

## Before you start

- Steam Deck with Decky Loader.
- NetworkManager managing the WireGuard connections you want to use.
- `wireguard-tools` for peer verification and connection diagnostics.
- Saved keys in each profile. Connections that need an interactive password
  prompt are not supported.

The backend needs root access to manage NetworkManager. Install only if you
trust the source. Profiles created only with `wg-quick` are not shown; import
their `.conf` file or add the profile through NetworkManager.

## Install

Download a ZIP from the
[GitHub Releases page](https://github.com/Polgonite/decky-wireguard/releases).
Releases are prereleases, not stable releases.

1. Enable Developer Mode in Decky Loader settings.
2. Choose **Install Plugin from ZIP File** and select the downloaded ZIP.
   Approve installation only if you trust the plugin.
3. Open **WireGuard** from the Decky quick-access panel.

If your Decky version does not offer ZIP installation, extract the archive so
the `decky-wireguard` directory is in `~/homebrew/plugins/` (or your configured
plugins directory), then restart Decky Loader. Do not install the source
directory without building it first.

## Get started

Select an existing profile, then choose **Connect**. To add one, select **Add connection**,
enter its settings or import a `.conf` file, then select **Save**. Importing
fills the editor; it does not save or connect the profile automatically.

Open **Edit configuration** to change a profile. On the same profile page,
use **Connect during boot** or **Smart connect** to set its startup behavior. See the
[configuration guide](docs/configuration.md) for detailed options and limits.

Your NetworkManager profile controls routing and DNS. The plugin does not
provide a kill switch or disconnect other tunnels.

## Updates

Open **Settings** from the connection list, choose **Update to latest build**,
and approve Decky's installation dialog. This needs an internet connection.
You can also install a downloaded release ZIP using Decky's plugin installer.

## Documentation

- [Configuration and startup](docs/configuration.md)
- [Troubleshooting and diagnostic logs](docs/troubleshooting.md)
- [How status checks and Smart connect work](docs/how-it-works.md)
- [Building, testing, and contributing](docs/development.md)
