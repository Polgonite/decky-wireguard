import asyncio
import logging
import os
import socket
import struct
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
from typing import Literal, TypedDict
from uuid import UUID


logger = logging.getLogger("decky-wireguard")

State = Literal["connected", "connecting", "disconnecting", "disconnected", "unknown"]
HandshakeState = Literal["inactive", "waiting", "established", "timeout", "unknown"]
HANDSHAKE_TIMEOUT = 30
PROBE_INTERVAL = 10
Address = IPv4Address | IPv6Address


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
               else "Install wireguard-tools to monitor peer handshakes.")
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
                return {"success": True, "profiles": statuses}
        except NetworkManagerError as error:
            return self._failure(error)

    async def set_connection(self, uuid: str, connected: bool) -> dict[str, object]:
        if not isinstance(uuid, str) or not isinstance(connected, bool):
            return self._failure(NetworkManagerError("A profile UUID and boolean state are required."))
        try:
            canonical_uuid = str(UUID(uuid))
        except ValueError:
            return self._failure(NetworkManagerError("Invalid connection UUID."))

        try:
            async with self._lock:
                profiles = await self._profiles()
                profile = next(
                    (profile for profile in profiles if profile["uuid"] == canonical_uuid),
                    None,
                )
                if profile is None:
                    raise NetworkManagerError(
                        "WireGuard profile not found. Refresh the list and try again."
                    )
                target: State = "connected" if connected else "disconnected"
                if profile["state"] == target:
                    return {"success": True}
                if profile["state"] in ("connecting", "disconnecting"):
                    raise NetworkManagerError(
                        "This profile is changing state. Wait and refresh before trying again."
                    )
                if profile["state"] == "unknown":
                    raise NetworkManagerError(
                        "This profile has an unknown state. Check it in NetworkManager."
                    )
                if connected:
                    self._activations.pop(canonical_uuid, None)
                    self._pending_activations[canonical_uuid] = (time.monotonic(), int(time.time()))
                await _nmcli(
                    "connection", "up" if connected else "down", "uuid", canonical_uuid, wait=30
                )
                if not connected:
                    self._activations.pop(canonical_uuid, None)
                    self._pending_activations.pop(canonical_uuid, None)
                return {"success": True}
        except NetworkManagerError as error:
            return self._failure(error)

    async def _main(self) -> None:
        logger.info("WireGuard plugin loaded.")

    async def _unload(self) -> None:
        logger.info("WireGuard plugin unloaded; existing connections are unchanged.")
