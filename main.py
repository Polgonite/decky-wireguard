import asyncio
import json
import logging
import os
import socket
import struct
import tempfile
import time
from dataclasses import dataclass
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_interface,
    ip_network,
)
from pathlib import Path
from typing import Literal, TypedDict
from uuid import UUID


logger = logging.getLogger("decky-wireguard")

State = Literal["connected", "connecting", "disconnecting", "disconnected", "unknown"]
HandshakeState = Literal["inactive", "waiting", "established", "timeout", "unknown"]
HANDSHAKE_TIMEOUT = 30
PROBE_INTERVAL = 10
Address = IPv4Address | IPv6Address
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
STEAM_READINESS_MAX_AGE = 10


class StartupRequirements(TypedDict):
    wait_for_steam: bool
    wait_for_internet: bool


def _default_requirements() -> StartupRequirements:
    return {"wait_for_steam": True, "wait_for_internet": True}


class StartupSettings(TypedDict):
    after_boot: list[str]
    last_boot_id: str | None
    requirements: dict[str, StartupRequirements]


class Profile(TypedDict):
    uuid: str
    name: str
    device: str
    state: State


class NetworkManagerError(Exception):
    pass


@dataclass
class Activation:
    path: str
    started: float
    since: int | None
    baseline: dict[str, int] | None = None
    completed: bool = False
    received: dict[str, int] | None = None
    targets: list["ProbeTarget"] | None = None
    last_probe: float | None = None


@dataclass(frozen=True)
class ProbeTarget:
    address: Address
    dns: bool = False


def _split_fields(line: str) -> list[str]:
    """Decode nmcli's terse colon-separated fields, including escaped colons."""
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for character in line:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(character)
    if escaped:
        raise NetworkManagerError("NetworkManager returned an incomplete escaped field.")
    fields.append("".join(current))
    return fields


async def _command(executable: str, *arguments: str, wait: int = 10) -> str:
    try:
        process = await asyncio.create_subprocess_exec(
            executable,
            *arguments,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        )
    except FileNotFoundError as error:
        raise NetworkManagerError(
            f"{executable} is not installed. "
            + ("This plugin requires NetworkManager and nmcli." if executable == "nmcli"
               else "Install wireguard-tools to monitor peer handshakes." if executable == "wg"
               else "This plugin requires systemd to detect when boot has finished.")
        ) from error
    except OSError as error:
        raise NetworkManagerError(f"Unable to start {executable}: {error}") from error

    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=wait + 5)
    except (asyncio.TimeoutError, asyncio.CancelledError) as error:
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass  # The process can exit between the returncode check and kill.
        await process.communicate()
        if isinstance(error, asyncio.CancelledError):
            raise
        raise NetworkManagerError(
            f"{executable} timed out. The operation may still finish; refresh its status."
        ) from error

    if process.returncode != 0:
        detail = (stderr or stdout).decode("utf-8", errors="replace").strip()
        raise NetworkManagerError(
            f"{executable} failed ({process.returncode}): {detail[:600] or 'No error details.'}"
        )
    return stdout.decode("utf-8", errors="replace")


async def _nmcli(*arguments: str, wait: int = 10) -> str:
    return await _command(
        "nmcli", "--terse", "--escape", "yes", "--colors", "no", "--wait", str(wait),
        *arguments, wait=wait,
    )


async def _handshakes(device: str) -> dict[str, int]:
    output = await _command("wg", "show", device, "latest-handshakes")
    handshakes: dict[str, int] = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) != 2 or not fields[1].isascii() or not fields[1].isdecimal():
            raise NetworkManagerError("WireGuard returned unexpected handshake data.")
        handshakes[fields[0]] = int(fields[1])
    return handshakes


async def _received_bytes(device: str) -> dict[str, int]:
    output = await _command("wg", "show", device, "transfer")
    received: dict[str, int] = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) != 3 or any(
            not value.isascii() or not value.isdecimal() for value in fields[1:]
        ):
            raise NetworkManagerError("WireGuard returned unexpected transfer data.")
        received[fields[0]] = int(fields[1])
    return received


def _unicast(address: Address) -> bool:
    return not (
        address.is_unspecified or address.is_loopback or address.is_multicast
        or address.is_link_local
        or (isinstance(address, IPv4Address) and (
            int(address) < int(IPv4Address("1.0.0.0"))
            or int(address) >= int(IPv4Address("240.0.0.0"))
        ))
    )


async def _probe_targets(device: str) -> list[ProbeTarget]:
    allowed_output = await _command("wg", "show", device, "allowed-ips")
    device_output = await _nmcli(
        "--fields", "IP4.ADDRESS,IP6.ADDRESS,IP4.DNS,IP6.DNS", "device", "show", device,
    )
    try:
        allowed: list[tuple[str, IPv4Network | IPv6Network]] = []
        for line in allowed_output.splitlines():
            peer, networks = line.split(maxsplit=1)
            if networks != "(none)":
                allowed.extend((peer, ip_network(value)) for value in networks.split())
        local: set[Address] = set()
        dns: list[Address] = []
        for line in device_output.splitlines():
            key, value = _split_fields(line)
            if not value or value == "--":
                continue
            if key.startswith(("IP4.ADDRESS[", "IP6.ADDRESS[")):
                local.add(ip_interface(value).ip)
            elif key.startswith(("IP4.DNS[", "IP6.DNS[")):
                dns.append(ip_address(value))
            else:
                raise ValueError("Unexpected device field")
    except ValueError as error:
        raise NetworkManagerError("Unable to parse WireGuard probe addresses.") from error

    def owner(address: Address) -> str | None:
        matches = [(net.prefixlen, peer) for peer, net in allowed if address in net]
        return max(matches)[1] if matches else None

    targets: list[ProbeTarget] = []
    for peer in dict.fromkeys(peer for peer, _ in allowed):
        for address in dns:
            if _unicast(address) and address not in local and owner(address) == peer:
                targets.append(ProbeTarget(address, dns=True))
                break
        for candidate_peer, network in allowed:
            if candidate_peer != peer:
                continue
            # Default routes need no real public host: queuing traffic triggers WireGuard.
            documentation = ip_address("192.0.2.1" if network.version == 4 else "2001:db8::1")
            if documentation in network:
                candidates = [documentation]
            else:
                first = int(network.network_address) + (network.num_addresses > 2)
                last = int(network.broadcast_address) - (
                    network.version == 4 and network.num_addresses > 2
                )
                candidates = [
                    type(network.network_address)(value)
                    for value in range(first, min(last + 1, first + len(local) + 2))
                ]
            address = next((
                address for address in candidates
                if _unicast(address) and address not in local and owner(address) == peer
            ), None)
            if address is not None:
                targets.append(ProbeTarget(address))
                break
    if not targets:
        raise NetworkManagerError("No usable remote address in this tunnel's AllowedIPs for a probe.")
    return targets


async def _send_probe(device: str, targets: list[ProbeTarget]) -> None:
    sent = False
    failures: list[str] = []
    for target in targets:
        ipv4 = target.address.version == 4
        family = socket.AF_INET if ipv4 else socket.AF_INET6
        protocol = socket.IPPROTO_UDP if target.dns else (
            socket.IPPROTO_ICMP if ipv4 else socket.IPPROTO_ICMPV6
        )
        try:
            try:
                probe_socket = socket.socket(family, socket.SOCK_DGRAM, protocol)
            except PermissionError:
                if target.dns:
                    raise
                # Some systems restrict ping sockets even for the root backend.
                probe_socket = socket.socket(family, socket.SOCK_RAW, protocol)
            with probe_socket as probe:
                # Fail closed: never let a probe fall back to Wi-Fi or another tunnel.
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, device.encode() + b"\0")
                probe.setblocking(False)
                if target.dns:
                    # Root NS query: no user hostname or external lookup service.
                    payload = os.urandom(2) + struct.pack("!5H", 0x0100, 1, 0, 0, 0) + b"\0\0\2\0\1"
                else:
                    # Checksum for this IPv4 echo header; IPv6 is supplied by the kernel.
                    checksum = ~((8 << 8) + 1) & 0xFFFF if ipv4 else 0
                    payload = struct.pack("!BBHHH", 8 if ipv4 else 128, 0, checksum, 0, 1)
                destination = (str(target.address), 53 if target.dns else 0)
                if not ipv4:
                    destination = (*destination, 0, 0)
                await asyncio.wait_for(
                    asyncio.get_running_loop().sock_sendto(probe, payload, destination), timeout=1,
                )
                sent = True
        except OSError as error:
            detail = f"Unable to send tunnel probe on {device} to {target.address}: {error}"
            logger.warning("%s", detail)
            failures.append(detail)
    if not sent:
        raise NetworkManagerError("; ".join(failures) or "No tunnel probe targets available.")


class Plugin:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._active_paths: dict[str, str] = {}
        self._activations: dict[str, Activation] = {}
        self._pending_activations: dict[str, tuple[float, int]] = {}
        self._startup_task: asyncio.Task[None] | None = None
        self._startup_error: str | None = None
        self._startup_waiting: dict[str, str] = {}
        self._startup_pending: set[str] = set()
        self._steam_ready = False
        self._steam_reported_at: float | None = None
        self._steam_error: str | None = None

    def _settings_path(self) -> Path:
        directory = os.environ.get("DECKY_PLUGIN_SETTINGS_DIR")
        if not directory:
            raise NetworkManagerError("Decky's plugin settings directory is unavailable.")
        return Path(directory) / "startup.json"

    def _read_settings(self) -> StartupSettings:
        path = self._settings_path()
        try:
            settings = json.loads(path.read_text())
            if (
                not isinstance(settings, dict)
                or not isinstance(settings.get("after_boot"), list)
                or any(
                    not isinstance(uuid, str) or str(UUID(uuid)) != uuid
                    for uuid in settings["after_boot"]
                )
                or (
                    settings.get("last_boot_id") is not None
                    and not isinstance(settings["last_boot_id"], str)
                )
            ):
                raise ValueError("Invalid startup settings")
            requirements = settings.get("requirements", {})
            if not isinstance(requirements, dict) or any(
                not isinstance(uuid, str) or str(UUID(uuid)) != uuid
                or not isinstance(options, dict)
                or any(not isinstance(options.get(key), bool) for key in _default_requirements())
                for uuid, options in requirements.items()
            ):
                raise ValueError("Invalid startup requirements")
            return {
                "after_boot": settings["after_boot"],
                "last_boot_id": settings.get("last_boot_id"),
                "requirements": requirements,
            }
        except FileNotFoundError:
            return {"after_boot": [], "last_boot_id": None, "requirements": {}}
        except (OSError, ValueError) as error:
            raise NetworkManagerError(f"Unable to read startup settings: {error}") from error

    def _write_settings(self, settings: StartupSettings) -> None:
        path = self._settings_path()
        temporary: str | None = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as output:
                    temporary = output.name
                    json.dump(settings, output)
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temporary, path)
            finally:
                if temporary is not None:
                    Path(temporary).unlink(missing_ok=True)
        except OSError as error:
            raise NetworkManagerError(f"Unable to save startup settings: {error}") from error

    async def _profile(self, uuid: str) -> Profile:
        if not isinstance(uuid, str):
            raise NetworkManagerError("A profile UUID is required.")
        try:
            canonical_uuid = str(UUID(uuid))
        except ValueError as error:
            raise NetworkManagerError("Invalid connection UUID.") from error
        profile = next(
            (profile for profile in await self._profiles() if profile["uuid"] == canonical_uuid),
            None,
        )
        if profile is None:
            raise NetworkManagerError("WireGuard profile not found. Refresh the list and try again.")
        return profile

    async def _autoconnect(self, uuid: str) -> bool:
        value = (await _nmcli(
            "--get-values", "connection.autoconnect", "connection", "show", "uuid", uuid,
        )).strip()
        if value not in ("yes", "no"):
            raise NetworkManagerError("NetworkManager returned unexpected autoconnect data.")
        return value == "yes"

    async def get_startup_settings(self, uuid: str) -> dict[str, object]:
        try:
            async with self._lock:
                profile = await self._profile(uuid)
                settings = self._read_settings()
                return {
                    "success": True,
                    "on_boot": await self._autoconnect(profile["uuid"]),
                    "after_boot": profile["uuid"] in settings["after_boot"],
                    **settings["requirements"].get(profile["uuid"], _default_requirements()),
                    "waiting": self._startup_waiting.get(profile["uuid"]),
                }
        except NetworkManagerError as error:
            return self._failure(error)

    async def set_startup_requirements(
        self, uuid: str, wait_for_steam: bool, wait_for_internet: bool,
    ) -> dict[str, object]:
        if not isinstance(wait_for_steam, bool) or not isinstance(wait_for_internet, bool):
            return self._failure(NetworkManagerError("Startup requirements must be boolean values."))
        try:
            async with self._lock:
                profile = await self._profile(uuid)
                settings = self._read_settings()
                settings["requirements"][profile["uuid"]] = {
                    "wait_for_steam": wait_for_steam, "wait_for_internet": wait_for_internet,
                }
                self._write_settings(settings)
                return {"success": True}
        except NetworkManagerError as error:
            return self._failure(error)

    async def set_steam_readiness(
        self, ready: bool, error: str | None = None,
    ) -> dict[str, object]:
        if not isinstance(ready, bool) or (error is not None and not isinstance(error, str)):
            return self._failure(NetworkManagerError("Invalid Steam readiness report."))
        if error and error != self._steam_error:
            logger.warning("Steam readiness unavailable: %s", error)
        self._steam_error = error
        self._steam_ready = ready and error is None
        self._steam_reported_at = time.monotonic()
        return {"success": True}

    def _steam_login_ready(self) -> bool:
        return (
            self._steam_ready
            and self._steam_reported_at is not None
            and time.monotonic() - self._steam_reported_at < STEAM_READINESS_MAX_AGE
        )

    async def _internet_ready(self) -> bool:
        # Without active checks NetworkManager can infer "full" from a default route.
        checks = await _command(
            "busctl", "--system", "get-property", "org.freedesktop.NetworkManager",
            "/org/freedesktop/NetworkManager", "org.freedesktop.NetworkManager",
            "ConnectivityCheckAvailable", "ConnectivityCheckEnabled",
        )
        if checks.splitlines() != ["b true", "b true"]:
            raise NetworkManagerError(
                "Internet readiness requires NetworkManager connectivity checking to be "
                "available and enabled. Enable it or turn off 'Wait for internet' for this profile."
            )
        connectivity = (await _nmcli("networking", "connectivity", "check")).strip()
        if connectivity not in ("unknown", "none", "portal", "limited", "full"):
            raise NetworkManagerError("NetworkManager returned unexpected internet connectivity data.")
        if connectivity != "full":
            return False
        output = await _nmcli(
            "--fields", "TYPE,STATE,IP4-CONNECTIVITY,IP6-CONNECTIVITY", "device", "status",
        )
        ready = False
        for line in output.splitlines():
            fields = _split_fields(line)
            if len(fields) != 4:
                raise NetworkManagerError("NetworkManager returned unexpected device connectivity data.")
            kind, state, ipv4, ipv6 = fields
            if any(value not in ("unknown", "none", "portal", "limited", "full") for value in (ipv4, ipv6)):
                raise NetworkManagerError("NetworkManager returned unexpected device connectivity data.")
            if kind in ("wifi", "ethernet", "gsm", "cdma", "bluetooth") and state == "connected":
                ready |= ipv4 == "full" or ipv6 == "full"
        return ready

    async def set_startup(self, uuid: str, mode: str) -> dict[str, object]:
        if mode not in ("off", "on_boot", "after_boot"):
            return self._failure(NetworkManagerError("Invalid startup mode."))
        try:
            async with self._lock:
                profile = await self._profile(uuid)
                uuid = profile["uuid"]
                settings = self._read_settings()
                # Disable the plugin first: a failed nmcli edit must not enable both modes.
                if mode != "after_boot" and uuid in settings["after_boot"]:
                    settings["after_boot"].remove(uuid)
                    self._write_settings(settings)
                await _nmcli(
                    "connection", "modify", "uuid", uuid,
                    "connection.autoconnect", "yes" if mode == "on_boot" else "no",
                )
                if mode == "after_boot" and uuid not in settings["after_boot"]:
                    settings["after_boot"].append(uuid)
                    self._write_settings(settings)
                return {"success": True}
        except NetworkManagerError as error:
            return self._failure(error)

    async def _profiles(self) -> list[Profile]:
        output = await _nmcli(
            "--fields", "UUID,TYPE,NAME,DEVICE,STATE,ACTIVE-PATH", "connection", "show"
        )
        states: dict[str, State] = {
            "activated": "connected",
            "activating": "connecting",
            "deactivating": "disconnecting",
            "deactivated": "disconnected",
            "": "disconnected",
            "--": "disconnected",
        }
        profiles: list[Profile] = []
        active_paths: dict[str, str] = {}
        for line in output.split("\n"):
            if not line:
                continue
            fields = _split_fields(line)
            if len(fields) != 6:
                raise NetworkManagerError("NetworkManager returned unexpected profile data.")
            uuid, kind, name, device, state, active_path = fields
            if kind != "wireguard":
                continue
            active_paths[uuid] = "" if active_path == "--" else active_path
            profiles.append({
                "uuid": uuid,
                "name": name,
                "device": "" if device == "--" else device,
                "state": states.get(state, "unknown"),
            })
        self._active_paths = active_paths
        return sorted(profiles, key=lambda profile: (profile["name"].casefold(), profile["uuid"]))

    async def _handshake_status(self, profile: Profile) -> HandshakeState:
        uuid = profile["uuid"]
        if profile["state"] not in ("connected", "connecting"):
            self._activations.pop(uuid, None)
            self._pending_activations.pop(uuid, None)
            return "unknown" if profile["state"] == "unknown" else "inactive"

        path = self._active_paths[uuid]
        if not path:
            raise NetworkManagerError("NetworkManager did not report an active connection path.")
        activation = self._activations.get(uuid)
        if activation is None or activation.path != path:
            pending = self._pending_activations.pop(uuid, None)
            activation = Activation(
                path=path,
                started=pending[0] if pending else time.monotonic(),
                since=pending[1] if pending else (
                    int(time.time()) if profile["state"] == "connecting" else None
                ),
            )
            self._activations[uuid] = activation
        if activation.completed:
            return "established"
        if profile["state"] == "connected":
            if not profile["device"]:
                raise NetworkManagerError("NetworkManager did not report a WireGuard interface.")
            handshakes = await _handshakes(profile["device"])
            if activation.baseline is None:
                activation.baseline = handshakes
            if any(
                timestamp > 0 and (
                    timestamp >= activation.since if activation.since is not None
                    else timestamp > activation.baseline.get(peer, 0)
                )
                for peer, timestamp in handshakes.items()
            ):
                activation.completed = True
                return "established"
            received = await _received_bytes(profile["device"])
            if activation.received is not None and any(
                peer in activation.received and amount > activation.received[peer]
                for peer, amount in received.items()
            ):
                activation.completed = True
                return "established"
            activation.received = received
            if activation.last_probe is None or (
                time.monotonic() - activation.last_probe >= PROBE_INTERVAL
            ):
                if activation.targets is None:
                    activation.targets = await _probe_targets(profile["device"])
                await _send_probe(profile["device"], activation.targets)
                activation.last_probe = time.monotonic()
        return "timeout" if time.monotonic() - activation.started >= HANDSHAKE_TIMEOUT else "waiting"

    def _failure(self, error: Exception) -> dict[str, object]:
        logger.warning("%s", error)
        return {"success": False, "error": str(error)}

    async def get_profiles(self) -> dict[str, object]:
        try:
            async with self._lock:
                profiles = await self._profiles()
                for uuid in self._activations.keys() - self._active_paths.keys():
                    del self._activations[uuid]
                for uuid in self._pending_activations.keys() - self._active_paths.keys():
                    del self._pending_activations[uuid]
                statuses: list[dict[str, object]] = []
                for profile in profiles:
                    error_message = None
                    try:
                        handshake = await self._handshake_status(profile)
                    except NetworkManagerError as error:
                        logger.warning("%s: %s", profile["name"], error)
                        handshake = "unknown"
                        error_message = str(error)
                    statuses.append({
                        **profile, "handshake": handshake, "handshake_error": error_message,
                    })
                result: dict[str, object] = {"success": True, "profiles": statuses}
                if self._startup_error is not None:
                    result["startup_error"] = self._startup_error
                return result
        except NetworkManagerError as error:
            return self._failure(error)

    async def set_connection(self, uuid: str, connected: bool) -> dict[str, object]:
        if not isinstance(uuid, str) or not isinstance(connected, bool):
            return self._failure(NetworkManagerError("A profile UUID and boolean state are required."))
        try:
            async with self._lock:
                profile = await self._profile(uuid)
                await self._change_connection(profile, connected)
                self._startup_pending.discard(profile["uuid"])
                self._startup_waiting.pop(profile["uuid"], None)
                return {"success": True}
        except NetworkManagerError as error:
            return self._failure(error)

    async def _change_connection(self, profile: Profile, connected: bool) -> None:
        uuid = profile["uuid"]
        target: State = "connected" if connected else "disconnected"
        if profile["state"] == target:
            return
        if profile["state"] in ("connecting", "disconnecting"):
            raise NetworkManagerError(
                "This profile is changing state. Wait and refresh before trying again."
            )
        if profile["state"] == "unknown":
            raise NetworkManagerError(
                "This profile has an unknown state. Check it in NetworkManager."
            )
        if connected:
            self._activations.pop(uuid, None)
            self._pending_activations[uuid] = (time.monotonic(), int(time.time()))
        await _nmcli("connection", "up" if connected else "down", "uuid", uuid, wait=30)
        if not connected:
            self._activations.pop(uuid, None)
            self._pending_activations.pop(uuid, None)

    async def _main(self) -> None:
        logger.info("WireGuard plugin loaded.")
        self._startup_task = asyncio.create_task(self._activate_after_boot())

    async def _activate_after_boot(self) -> None:
        try:
            async with self._lock:
                settings = self._read_settings()
                try:
                    boot_id = str(UUID(BOOT_ID_PATH.read_text().strip()))
                except (OSError, ValueError) as error:
                    raise NetworkManagerError(f"Unable to identify this boot: {error}") from error
                if settings["last_boot_id"] == boot_id:
                    return
                # Claim this boot even with no configured profiles, before any activation.
                settings["last_boot_id"] = boot_id
                self._write_settings(settings)
                configured = settings["after_boot"].copy()
                self._startup_pending = set(configured)
                self._startup_waiting = {uuid: "Waiting for system boot to finish." for uuid in configured}
            if not configured:
                return
            while True:
                state = (await _command(
                    "systemctl", "show", "--property=SystemState", "--value",
                )).strip()
                if state in ("running", "degraded"):
                    break
                if state not in ("initializing", "starting"):
                    raise NetworkManagerError(f"Cannot connect after boot: system state is {state!r}.")
                await asyncio.sleep(2)
            while self._startup_pending:
                for uuid in configured:
                    if uuid not in self._startup_pending:
                        continue
                    waiting = False
                    try:
                        async with self._lock:
                            settings = self._read_settings()
                            if uuid not in settings["after_boot"]:
                                continue
                            profile = await self._profile(uuid)
                            if await self._autoconnect(uuid):
                                raise NetworkManagerError(
                                    "NetworkManager autoconnect is enabled; "
                                    "select a startup mode again to resolve the conflict."
                                )
                            if profile["state"] in ("connected", "connecting"):
                                continue
                            options = settings["requirements"].get(uuid, _default_requirements())
                            if options["wait_for_steam"] and not self._steam_login_ready():
                                self._startup_waiting[uuid] = (
                                    f"Steam readiness unavailable: {self._steam_error}"
                                    if self._steam_error else "Waiting for Steam login or Offline Mode."
                                )
                                waiting = True
                                continue
                            if options["wait_for_internet"] and not await self._internet_ready():
                                self._startup_waiting[uuid] = "Waiting for internet on a non-VPN connection."
                                waiting = True
                                continue
                            # Recheck the heartbeat after the potentially slow connectivity check.
                            if options["wait_for_steam"] and not self._steam_login_ready():
                                self._startup_waiting[uuid] = "Waiting for Steam login or Offline Mode."
                                waiting = True
                                continue
                            await self._change_connection(profile, True)
                    except NetworkManagerError as error:
                        message = f"After-boot connection failed for {uuid}: {error}"
                        logger.warning("%s", message)
                        self._startup_error = (
                            f"{self._startup_error}\n{message}" if self._startup_error else message
                        )
                    finally:
                        if not waiting:
                            self._startup_pending.discard(uuid)
                            self._startup_waiting.pop(uuid, None)
                if self._startup_pending:
                    await asyncio.sleep(5)
        except NetworkManagerError as error:
            logger.warning("After-boot connection: %s", error)
            self._startup_error = str(error)
        finally:
            self._startup_pending.clear()
            self._startup_waiting.clear()

    async def _unload(self) -> None:
        if self._startup_task is not None:
            self._startup_task.cancel()
            try:
                await self._startup_task
            except asyncio.CancelledError:
                pass
        logger.info("WireGuard plugin unloaded; existing connections are unchanged.")
