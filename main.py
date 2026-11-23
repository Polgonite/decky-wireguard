import asyncio
import base64
import copy
import json
import logging
import os
import re
import socket
import stat
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
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Literal, TypedDict
from uuid import UUID, uuid4

logger = logging.getLogger("decky-wireguard")

State = Literal["connected", "connecting", "disconnecting", "disconnected", "unknown"]
HandshakeState = Literal["inactive", "waiting", "established", "timeout", "unknown"]
HANDSHAKE_TIMEOUT = 30
PROBE_INTERVAL = 10
Address = IPv4Address | IPv6Address
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
STEAM_READINESS_MAX_AGE = 10
DIAGNOSTIC_LOG = "wireguard-diagnostics.log"
NM_SERVICE = "org.freedesktop.NetworkManager"
NM_SETTINGS_PATH = "/org/freedesktop/NetworkManager/Settings"
NM_CONNECTION_INTERFACE = "org.freedesktop.NetworkManager.Settings.Connection"
SECRET_NOT_REQUIRED = 4
# IP methods that NetworkManager rejects alongside addresses, DNS servers or search domains.
NO_ADDRESS_METHODS = (None, "disabled", "ignore", "link-local")
CONFIG_FIELDS = ("name", "private_key", "addresses", "dns", "mtu", "listen_port", "peers")
PEER_FIELDS = (
    "original_public_key", "public_key", "preshared_key", "allowed_ips", "endpoint",
    "persistent_keepalive",
)
# Edited through the WireGuard editor instead of as raw NetworkManager properties.
STRUCTURED_PROPERTIES = frozenset({
    "connection.autoconnect", "connection.id", "wireguard.private-key", "wireguard.peers",
    "wireguard.mtu", "wireguard.listen-port", "ipv4.addresses", "ipv6.addresses",
    "ipv4.dns", "ipv6.dns", "ipv4.dns-search", "ipv6.dns-search",
})
IDENTITY_PROPERTIES = frozenset({"connection.uuid", "connection.type"})
Settings = dict[str, dict[str, dict[str, object]]]


class StartupRequirements(TypedDict):
    wait_for_steam: bool
    wait_for_internet: bool


def _default_requirements() -> StartupRequirements:
    return {"wait_for_steam": True, "wait_for_internet": True}


class StartupSettings(TypedDict):
    after_boot: list[str]
    last_boot_id: str | None
    requirements: dict[str, StartupRequirements]


class LoggingSettings(TypedDict):
    enabled: bool
    debug: bool


class UISettings(TypedDict):
    show_advanced_settings: bool


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
               else "This plugin requires systemd's busctl to query NetworkManager."
               if executable == "busctl"
               else "This plugin requires systemd to detect when boot has finished.")
        ) from error
    except OSError as error:
        raise NetworkManagerError(f"Unable to start {executable}: {error}") from error

    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=wait + 5)
    except (TimeoutError, asyncio.CancelledError) as error:
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


def _complete_type_end(signature: str, start: int) -> int:
    if start >= len(signature):
        raise ValueError("Truncated D-Bus signature")
    code = signature[start]
    if code == "a":
        return _complete_type_end(signature, start + 1)
    if code in "({":
        close = ")" if code == "(" else "}"
        index = start + 1
        while index < len(signature) and signature[index] != close:
            index = _complete_type_end(signature, index)
        if index >= len(signature) or index == start + 1:
            raise ValueError("Unterminated D-Bus container signature")
        return index + 1
    if code in "ybnqiuxtdsogv":
        return start + 1
    raise ValueError(f"Unsupported D-Bus type {code!r}")


def _split_signature(signature: str) -> list[str]:
    types: list[str] = []
    index = 0
    while index < len(signature):
        end = _complete_type_end(signature, index)
        types.append(signature[index:end])
        index = end
    return types


def _encode_bus_value(signature: str, value: object) -> list[str]:
    """Encode busctl JSON-shaped data as busctl call arguments for one complete type."""
    code = signature[0]
    if code == "a":
        element = signature[1:]
        if element.startswith("{"):
            key_type, value_type = _split_signature(element[1:-1])
            if not isinstance(value, dict):
                raise TypeError("Expected a D-Bus dictionary")
            arguments = [str(len(value))]
            for key, item in value.items():
                arguments += _encode_bus_value(key_type, key) + _encode_bus_value(value_type, item)
            return arguments
        if not isinstance(value, list):
            raise TypeError("Expected a D-Bus array")
        return [str(len(value)), *(
            argument for item in value for argument in _encode_bus_value(element, item)
        )]
    if code == "(":
        types = _split_signature(signature[1:-1])
        if not isinstance(value, list) or len(value) != len(types):
            raise TypeError("Expected a D-Bus struct")
        return [
            argument for kind, item in zip(types, value)
            for argument in _encode_bus_value(kind, item)
        ]
    if code == "v":
        if (
            not isinstance(value, dict) or set(value) != {"type", "data"}
            or not isinstance(value["type"], str) or len(_split_signature(value["type"])) != 1
        ):
            raise TypeError("Expected a D-Bus variant")
        return [value["type"], *_encode_bus_value(value["type"], value["data"])]
    if code == "b":
        if not isinstance(value, bool):
            raise TypeError("Expected a D-Bus boolean")
        return ["true" if value else "false"]
    if code in "sog":
        if not isinstance(value, str):
            raise TypeError("Expected a D-Bus string")
        return [value]
    if code == "d":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError("Expected a D-Bus double")
        return [repr(float(value))]
    # Integer dictionary keys arrive as JSON object keys, so accept decimal strings too.
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise TypeError("Expected a D-Bus integer")
    return [str(int(value))]


async def _busctl(
    path: str, interface: str, method: str, signature: str = "", *arguments: str,
) -> list[object]:
    output = await _command(
        "busctl", "--system", "--json=short", "--timeout=10", "--",
        "call", NM_SERVICE, path, interface, method, signature, *arguments,
    )
    if not output.strip():
        return []
    try:
        reply = json.loads(output)
    except ValueError as error:
        raise NetworkManagerError("NetworkManager returned an unreadable D-Bus reply.") from error
    if not isinstance(reply, dict) or not isinstance(reply.get("data"), list):
        raise NetworkManagerError("NetworkManager returned an unexpected D-Bus reply.")
    return reply["data"]


def _settings_reply(data: list[object]) -> Settings:
    settings = data[0] if len(data) == 1 else None
    if not isinstance(settings, dict) or any(
        not isinstance(values, dict) or any(
            not isinstance(value, dict) or set(value) != {"type", "data"}
            or not isinstance(value["type"], str)
            for value in values.values()
        )
        for values in settings.values()
    ):
        raise NetworkManagerError("NetworkManager returned unexpected connection settings.")
    return settings


async def _nm_connection(uuid: str) -> tuple[str, Settings]:
    """Return a profile's D-Bus path and its settings, including WireGuard secrets."""
    reply = await _busctl(
        NM_SETTINGS_PATH, "org.freedesktop.NetworkManager.Settings",
        "GetConnectionByUuid", "s", uuid,
    )
    path = reply[0] if len(reply) == 1 else None
    if not isinstance(path, str) or not path.startswith("/"):
        raise NetworkManagerError("NetworkManager returned an unexpected connection path.")
    settings = _settings_reply(await _busctl(path, NM_CONNECTION_INTERFACE, "GetSettings"))
    secrets = _settings_reply(await _busctl(
        path, NM_CONNECTION_INTERFACE, "GetSecrets", "s", "wireguard",
    ))
    try:
        for name, values in secrets.items():
            target = settings.setdefault(name, {})
            for key, value in values.items():
                if name != "wireguard" or key != "peers":
                    target[key] = value
                    continue
                # Peer secrets arrive as separate dictionaries identified by public key.
                peers = {
                    peer["public-key"]["data"]: peer
                    for peer in target.get("peers", {"data": []})["data"]
                }
                for secret in value["data"]:
                    peer = peers.get(secret["public-key"]["data"])
                    if peer is not None:
                        peer.update({
                            field: item for field, item in secret.items() if field != "public-key"
                        })
    except (KeyError, TypeError) as error:
        raise NetworkManagerError("NetworkManager returned unexpected WireGuard secrets.") from error
    return path, settings


async def _nm_update(path: str, settings: Settings) -> None:
    payload = copy.deepcopy(settings)
    for family in ("ipv4", "ipv6"):
        values = payload.get(family, {})
        # NetworkManager prefers deprecated properties when sent, ignoring their replacements.
        for legacy, replacement in (
            ("addresses", "address-data"), ("routes", "route-data"), ("dns", "dns-data"),
        ):
            if replacement in values:
                values.pop(legacy, None)
    try:
        arguments = _encode_bus_value("a{sa{sv}}", payload)
    except (TypeError, ValueError) as error:
        raise NetworkManagerError(f"Unable to encode connection settings: {error}") from error
    await _busctl(path, NM_CONNECTION_INTERFACE, "Update", "a{sa{sv}}", *arguments)


def _variant(kind: str, data: object) -> dict[str, object]:
    return {"type": kind, "data": data}


def _data(values: dict[str, dict[str, object]], key: str, default: object) -> object:
    value = values.get(key)
    return default if value is None else value["data"]


def _entries(text: str) -> list[str]:
    return [entry for entry in re.split(r"[\s,]+", text) if entry]


def _hostname(text: str) -> bool:
    labels = text.removesuffix(".").split(".")
    return 0 < len(text) <= 253 and all(
        re.fullmatch(r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?", label)
        for label in labels
    )


def _dns_servers(values: dict[str, dict[str, object]], version: int) -> list[str]:
    if "dns-data" in values:
        return [str(server) for server in _data(values, "dns-data", [])]
    if version == 4:
        # NetworkManager sends IPv4 DNS as network-byte-order integers in host order.
        return [
            str(IPv4Address(struct.pack("=I", server))) for server in _data(values, "dns", [])
        ]
    return [str(IPv6Address(bytes(server))) for server in _data(values, "dns", [])]


def _peer_config(peer: dict[str, dict[str, object]]) -> dict[str, object]:
    public_key = str(_data(peer, "public-key", ""))
    keepalive = int(_data(peer, "persistent-keepalive", 0))
    return {
        "original_public_key": public_key,
        "public_key": public_key,
        "preshared_key": str(_data(peer, "preshared-key", "")),
        "allowed_ips": ", ".join(str(network) for network in _data(peer, "allowed-ips", [])),
        "endpoint": str(_data(peer, "endpoint", "")),
        "persistent_keepalive": str(keepalive) if keepalive else "",
    }


def _wireguard_config(settings: Settings) -> dict[str, object]:
    """Represent NetworkManager settings with the fields of a WireGuard .conf file."""
    try:
        families = {4: settings.get("ipv4", {}), 6: settings.get("ipv6", {})}
        wireguard = settings.get("wireguard", {})
        addresses = [
            f"{address['address']['data']}/{address['prefix']['data']}"
            for values in families.values() for address in _data(values, "address-data", [])
        ]
        servers = [
            server for version, values in families.items()
            for server in _dns_servers(values, version)
        ]
        domains = [
            str(domain) for values in families.values() for domain in _data(values, "dns-search", [])
        ]
        mtu = int(_data(wireguard, "mtu", 0))
        port = int(_data(wireguard, "listen-port", 0))
        return {
            "name": str(settings["connection"]["id"]["data"]),
            "private_key": str(_data(wireguard, "private-key", "")),
            "addresses": ", ".join(addresses),
            "dns": ", ".join(dict.fromkeys(servers + domains)),
            "mtu": str(mtu) if mtu else "",
            "listen_port": str(port) if port else "",
            "peers": [_peer_config(peer) for peer in _data(wireguard, "peers", [])],
        }
    except (KeyError, TypeError, ValueError) as error:
        raise NetworkManagerError("NetworkManager returned unexpected WireGuard settings.") from error


def _wireguard_key(text: str, label: str, required: bool) -> str:
    key = text.strip()
    if not key:
        if required:
            raise NetworkManagerError(f"{label} is required.")
        return ""
    try:
        decoded = base64.b64decode(key, validate=True)
        valid = len(decoded) == 32 and base64.b64encode(decoded).decode("ascii") == key
    except ValueError:
        valid = False
    if not valid:
        raise NetworkManagerError(f"{label} must be a 44-character base64 WireGuard key.")
    return key


def _number(
    text: str, label: str, maximum: int, off: bool = False, hexadecimal: bool = False,
) -> int:
    value = text.strip()
    if not value or (off and value.lower() == "off"):
        return 0
    base = 16 if hexadecimal and value.lower().startswith("0x") else 10
    digits = value[2:] if base == 16 else value
    pattern = r"[0-9a-fA-F]+" if base == 16 else r"[0-9]+"
    significant = digits.lstrip("0") or "0"
    # Bound conversion so long inputs cannot hit Python's integer-string limit.
    if (
        not re.fullmatch(pattern, digits)
        or len(significant) > len(str(maximum))
        or int(significant, base) > maximum
    ):
        formats = " (decimal or 0x hexadecimal)" if hexadecimal else ""
        disabled = ', "off"' if off else ""
        raise NetworkManagerError(
            f"{label} must be a whole number from 0 to {maximum}{formats}{disabled}, or empty."
        )
    return int(significant, base)


def _endpoint(text: str, label: str) -> str:
    endpoint = text.strip()
    if not endpoint:
        return ""
    host, separator, port = endpoint.rpartition(":")
    valid = bool(separator and host) and bool(re.fullmatch(r"[0-9]+", port))
    if valid:
        try:
            valid = 1 <= _number(port, f"{label} endpoint port", 65535)
        except NetworkManagerError:
            valid = False
    if valid and host.startswith("["):
        try:
            valid = host.endswith("]") and ip_address(host[1:-1]).version == 6
        except ValueError:
            valid = False
    elif valid:
        try:
            valid = ip_address(host).version == 4
        except ValueError:
            valid = ":" not in host and not re.fullmatch(r"[0-9.]+", host) and _hostname(host)
    if not valid:
        raise NetworkManagerError(
            f"{label} must be host:port, for example vpn.example.com:51820 or [2001:db8::1]:51820."
        )
    return endpoint


def _apply_peers(
    wireguard: dict[str, dict[str, object]], peers: list[dict[str, object]],
) -> list[dict[str, object]]:
    existing = {peer["public-key"]["data"]: peer for peer in _data(wireguard, "peers", [])}
    result: list[dict[str, object]] = []
    seen: set[str] = set()
    for index, peer in enumerate(peers, 1):
        label = f"Peer {index}"
        public_key = _wireguard_key(str(peer["public_key"]), f"{label} public key", True)
        if public_key in seen:
            raise NetworkManagerError(f"{label} uses the same public key as another peer.")
        seen.add(public_key)
        original = peer["original_public_key"]
        if original is not None and original not in existing:
            raise NetworkManagerError(
                f"{label} was changed outside this editor. Reload the configuration and try again."
            )
        # Start from the stored peer to keep properties this editor does not show.
        values = {} if original is None else copy.deepcopy(existing[original])
        values["public-key"] = _variant("s", public_key)
        allowed: list[str] = []
        for entry in _entries(str(peer["allowed_ips"])):
            try:
                if "%" in entry:
                    raise ValueError("Scoped addresses are not allowed in networks")
                allowed.append(str(ip_network(entry, strict=False)))
            except ValueError as error:
                raise NetworkManagerError(
                    f"{label} allowed IPs: {entry!r} is not an IP address or network."
                ) from error
        values["allowed-ips"] = _variant("as", allowed)
        endpoint = _endpoint(str(peer["endpoint"]), label)
        if endpoint:
            values["endpoint"] = _variant("s", endpoint)
        else:
            values.pop("endpoint", None)
        values["persistent-keepalive"] = _variant("u", _number(
            str(peer["persistent_keepalive"]), f"{label} persistent keepalive", 65535, off=True,
        ))
        preshared_key = _wireguard_key(str(peer["preshared_key"]), f"{label} preshared key", False)
        if original is None or preshared_key != _data(values, "preshared-key", ""):
            if preshared_key:
                values["preshared-key"] = _variant("s", preshared_key)
            else:
                values.pop("preshared-key", None)
            # Without NOT_REQUIRED, a peer lacking a preshared key makes activation ask for one.
            values["preshared-key-flags"] = _variant(
                "u", 0 if preshared_key else SECRET_NOT_REQUIRED,
            )
        result.append(values)
    return result


def _config_addresses(text: str) -> dict[int, list[dict[str, object]]]:
    addresses: dict[int, list[dict[str, object]]] = {4: [], 6: []}
    for entry in _entries(text):
        try:
            if "%" in entry:
                raise ValueError("Scoped addresses are not allowed on an interface")
            interface = ip_interface(entry)
        except ValueError as error:
            raise NetworkManagerError(
                f"Address: {entry!r} is not an IPv4 or IPv6 address with an optional CIDR prefix "
                "(0-32 for IPv4, 0-128 for IPv6)."
            ) from error
        addresses[interface.version].append({
            "address": _variant("s", str(interface.ip)),
            "prefix": _variant("u", interface.network.prefixlen),
        })
    return addresses


def _config_dns(text: str) -> tuple[dict[int, list[str]], list[str]]:
    servers: dict[int, list[str]] = {4: [], 6: []}
    domains: list[str] = []
    for entry in _entries(text):
        address, marker, server_name = entry.partition("#")
        try:
            server = ip_address(address)
        except ValueError:
            domain = entry.removeprefix("~")
            if (
                marker or (domain != "." and re.fullmatch(r"[0-9.]+", domain))
                or (not _hostname(domain) and entry not in (".", "~", "~."))
            ):
                raise NetworkManagerError(
                    f"DNS: {entry!r} is not an IP address or search domain."
                ) from None
            domains.append(entry)
        else:
            if "%" in address or (marker and not _hostname(server_name)):
                raise NetworkManagerError("DNS: invalid server address or DNS-over-TLS server name.")
            servers[server.version].append(entry)
    return servers, domains


def _validate_wireguard_settings(
    settings: Settings, advanced: list[dict[str, str]],
) -> None:
    updates = {update["key"]: update["value"] for update in advanced}
    name = updates.get(
        "connection.interface-name",
        str(_data(settings.get("connection", {}), "interface-name", "")),
    )
    try:
        name_length = len(name.encode("utf-8"))
    except UnicodeError as error:
        raise NetworkManagerError("Interface name must be valid UTF-8.") from error
    if (
        not name or name_length > 15 or name in (".", "..")
        or any(character.isspace() or character in "/:\0" for character in name)
    ):
        raise NetworkManagerError(
            "Interface name must be 1-15 UTF-8 bytes, not '.' or '..', "
            "and contain no whitespace, slash, colon or NUL."
        )
    for version, supported in (
        (4, ("manual", "disabled")),
        (6, ("manual", "disabled", "ignore", "link-local")),
    ):
        family = f"ipv{version}"
        values = settings.get(family, {})
        method = updates.get(f"{family}.method", _data(values, "method", "disabled"))
        if method not in supported:
            raise NetworkManagerError(
                f"{family}.method: WireGuard supports only {', '.join(supported)}."
            )
        addresses = _data(values, "address-data", [])
        if method == "manual" and not addresses:
            raise NetworkManagerError(
                f"{family}.method: manual requires at least one IPv{version} address in Address."
            )
        if method in NO_ADDRESS_METHODS:
            if addresses:
                raise NetworkManagerError(
                    f"{family}.method: {method} cannot be combined with static addresses."
                )
            if _dns_servers(values, version) or _data(values, "dns-search", []):
                raise NetworkManagerError(
                    f"DNS: IPv{version} DNS servers need an IPv{version} tunnel address in Address. "
                    f"Remove DNS/search domains or use {family}.method manual with an address."
                )


def _validate_advanced_names(keys: list[str]) -> None:
    guarded = STRUCTURED_PROPERTIES | IDENTITY_PROPERTIES | {
        "connection.interface-name", "ipv4.method", "ipv6.method", "wireguard.fwmark",
    }
    for key in keys:
        if key in guarded:
            continue
        group, _, field = key.partition(".")
        group = {"ip4": "ipv4", "ip6": "ipv6"}.get(group, group)
        for full in sorted(guarded):
            full_group, _, full_field = full.partition(".")
            if full_group.startswith(group) and full_field.startswith(field):
                raise NetworkManagerError(
                    f"Use the full property name {full!r} instead of the abbreviation {key!r}."
                )


def _apply_wireguard_config(
    settings: Settings, config: dict[str, object], advanced: list[dict[str, str]] | None = None,
) -> bool:
    """Validate the entire draft, but apply only changed fields to preserve other settings."""
    current = _wireguard_config(settings)
    changed = {field for field in CONFIG_FIELDS if config[field] != current[field]}
    name = str(config["name"]).strip()
    if not name or "\0" in name:
        raise NetworkManagerError("Name is required and must not contain NUL characters.")
    try:
        name.encode("utf-8")
    except UnicodeError as error:
        raise NetworkManagerError("Name must be valid UTF-8.") from error
    private_key = _wireguard_key(str(config["private_key"]), "Private key", True)
    mtu = _number(str(config["mtu"]), "MTU", 2**32 - 1)
    port = _number(str(config["listen_port"]), "Listen port", 65535)
    addresses = _config_addresses(str(config["addresses"]))
    servers, domains = _config_dns(str(config["dns"]))
    connection = settings.setdefault("connection", {})
    wireguard = settings.setdefault("wireguard", {})
    families = {4: settings.setdefault("ipv4", {}), 6: settings.setdefault("ipv6", {})}
    peers = _apply_peers(wireguard, config["peers"])
    if "name" in changed:
        connection["id"] = _variant("s", name)
    if "private_key" in changed:
        wireguard["private-key"] = _variant("s", private_key)
        wireguard["private-key-flags"] = _variant("u", 0)
    if "mtu" in changed:
        wireguard["mtu"] = _variant("u", mtu)
    if "listen_port" in changed:
        wireguard["listen-port"] = _variant("u", port)
    if "peers" in changed:
        wireguard["peers"] = _variant("aa{sv}", peers)
    if "addresses" in changed:
        for version, values in families.items():
            values["address-data"] = _variant("aa{sv}", addresses[version])
            method = _data(values, "method", None)
            if addresses[version] and method in NO_ADDRESS_METHODS:
                values["method"] = _variant("s", "manual")
            elif not addresses[version] and method == "manual":
                values["method"] = _variant("s", "disabled")
    # Address changes can disable a family, so search domains may need to move.
    if changed & {"addresses", "dns"}:
        for version, values in families.items():
            if "dns-data" in values:
                values["dns-data"] = _variant("as", servers[version])
            elif any("#" in server for server in servers[version]):
                raise NetworkManagerError(
                    "DNS-over-TLS server names require NetworkManager dns-data support."
                )
            elif version == 4:
                values["dns"] = _variant("au", [
                    struct.unpack("=I", ip_address(server).packed)[0] for server in servers[4]
                ])
            else:
                values["dns"] = _variant("aay", [
                    list(ip_address(server).packed) for server in servers[6]
                ])
            values["dns-search"] = _variant("as", [])
        if domains:
            family = next((
                values for values in families.values()
                if _data(values, "method", None) not in NO_ADDRESS_METHODS
            ), None)
            if family is None:
                raise NetworkManagerError("DNS: search domains need a tunnel address in Address.")
            family["dns-search"] = _variant("as", domains)
    _validate_wireguard_settings(settings, advanced or [])
    return bool(changed)


def _config_input(config: object) -> bool:
    return (
        isinstance(config, dict) and set(config) == set(CONFIG_FIELDS)
        and all(
            isinstance(config[field], str) and len(config[field]) <= 16384
            for field in CONFIG_FIELDS if field != "peers"
        )
        and isinstance(config["peers"], list) and len(config["peers"]) <= 64
        and all(
            isinstance(peer, dict) and set(peer) == set(PEER_FIELDS)
            and all(
                isinstance(peer[field], str) and len(peer[field]) <= 16384
                for field in PEER_FIELDS if field != "original_public_key"
            )
            and (peer["original_public_key"] is None or isinstance(peer["original_public_key"], str))
            for peer in config["peers"]
        )
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


async def _transfer_counters(device: str) -> dict[str, tuple[int, int]]:
    output = await _command("wg", "show", device, "transfer")
    counters: dict[str, tuple[int, int]] = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) != 3 or any(
            not value.isascii() or not value.isdecimal() for value in fields[1:]
        ):
            raise NetworkManagerError("WireGuard returned unexpected transfer data.")
        counters[fields[0]] = (int(fields[1]), int(fields[2]))
    return counters


async def _received_bytes(device: str) -> dict[str, int]:
    return {
        peer: received
        for peer, (received, _) in (await _transfer_counters(device)).items()
    }


async def _endpoints(device: str) -> dict[str, str]:
    output = await _command("wg", "show", device, "endpoints")
    endpoints: dict[str, str] = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) != 2:
            raise NetworkManagerError("WireGuard returned unexpected endpoint data.")
        endpoints[fields[0]] = fields[1]
    return endpoints


def _endpoint_ip(endpoint: str | None) -> str | None:
    # `wg show endpoints` prints "(none)", "host:port" or "[v6]:port".
    if not endpoint or endpoint == "(none)":
        return None
    host = endpoint.rpartition(":")[0]
    return host[1:-1] if host.startswith("[") and host.endswith("]") else host or None


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


async def _send_probe(device: str, targets: list[ProbeTarget]) -> int:
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
            logger.warning("Tunnel probe send failed (errno=%s).", error.errno)
            failures.append(detail)
    if not sent:
        raise NetworkManagerError("; ".join(failures) or "No tunnel probe targets available.")
    return len(failures)


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
        self._logging: LoggingSettings = {"enabled": False, "debug": False}
        self._logging_error: str | None = None
        self._log_session = uuid4().hex[:12]
        self._diagnostics = logging.getLogger(f"wireguard-diagnostics.{self._log_session}")
        self._diagnostics.propagate = False
        self._log_handler: RotatingFileHandler | None = None
        self._suspended_time: float | None = None
        self._profile_refs: dict[str, int] = {}
        self._peer_refs: dict[str, dict[str, int]] = {}
        self._logged_statuses: dict[str, tuple[State, HandshakeState]] = {}
        self._debug_samples: dict[str, float] = {}
        self._peer_samples: dict[
            str, tuple[dict[str, str], dict[str, tuple[int, int]]]
        ] = {}

    def _settings_path(self, filename: str = "startup.json") -> Path:
        directory = os.environ.get("DECKY_PLUGIN_SETTINGS_DIR")
        if not directory:
            raise NetworkManagerError("Decky's plugin settings directory is unavailable.")
        return Path(directory) / filename

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
        self._write_json(self._settings_path(), settings, "startup")

    @staticmethod
    def _write_json(
        path: Path, settings: StartupSettings | LoggingSettings | UISettings, label: str,
    ) -> None:
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
            raise NetworkManagerError(f"Unable to save {label} settings: {error}") from error

    async def get_ui_settings(self) -> dict[str, object]:
        try:
            try:
                settings = json.loads(self._settings_path("ui.json").read_text())
            except FileNotFoundError:
                return {"success": True, "show_advanced_settings": False}
            if not isinstance(settings, dict) or not isinstance(settings.get("show_advanced_settings"), bool):
                raise ValueError("Invalid UI settings")
            return {"success": True, "show_advanced_settings": settings["show_advanced_settings"]}
        except (OSError, ValueError, NetworkManagerError) as error:
            return self._failure(NetworkManagerError(f"Unable to read UI settings: {error}"))

    async def set_ui_settings(self, show_advanced_settings: bool) -> dict[str, object]:
        if not isinstance(show_advanced_settings, bool):
            return self._failure(NetworkManagerError("Show advanced settings must be a boolean."))
        settings: UISettings = {"show_advanced_settings": show_advanced_settings}
        try:
            self._write_json(self._settings_path("ui.json"), settings, "UI")
        except NetworkManagerError as error:
            return self._failure(error)
        return {"success": True, **settings}

    def _open_diagnostic_log(self) -> RotatingFileHandler:
        directory = os.environ.get("DECKY_PLUGIN_LOG_DIR")
        if not directory:
            raise NetworkManagerError("Decky's plugin log directory is unavailable.")
        try:
            path = Path(directory) / DIAGNOSTIC_LOG
            path.parent.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(path, maxBytes=256 * 1024, backupCount=1, encoding="utf-8")
        except OSError as error:
            raise NetworkManagerError("Unable to open the WireGuard diagnostics log.") from error
        formatter = logging.Formatter("%(asctime)sZ %(levelname)s %(message)s", "%Y-%m-%dT%H:%M:%S")
        formatter.converter = time.gmtime
        handler.setFormatter(formatter)
        return handler

    def _configure_logging(
        self, settings: LoggingSettings, handler: RotatingFileHandler | None,
    ) -> None:
        if not settings["enabled"]:
            self._log(logging.INFO, "logging_disabled")
        if handler is not self._log_handler:
            if self._log_handler is not None:
                self._diagnostics.removeHandler(self._log_handler)
                self._log_handler.close()
            self._log_handler = handler
            if handler is not None:
                self._diagnostics.addHandler(handler)
        self._logging = settings
        self._logging_error = None
        self._diagnostics.setLevel(logging.DEBUG if settings["debug"] else logging.INFO)
        self._logged_statuses.clear()
        self._debug_samples.clear()
        self._peer_samples.clear()
        self._suspended_time = None
        if settings["enabled"]:
            self._log(logging.INFO, "logging_enabled debug=%s", settings["debug"])
            self._observe_resume()

    def _load_logging(self) -> None:
        try:
            try:
                settings = json.loads(self._settings_path("logging.json").read_text())
            except FileNotFoundError:
                return
            if (
                not isinstance(settings, dict)
                or any(not isinstance(settings.get(key), bool) for key in ("enabled", "debug"))
                or (settings["debug"] and not settings["enabled"])
            ):
                raise ValueError("Invalid logging settings")
            self._logging = {"enabled": settings["enabled"], "debug": settings["debug"]}
            handler = self._open_diagnostic_log() if settings["enabled"] else None
            self._configure_logging(self._logging, handler)
        except (OSError, ValueError, NetworkManagerError):
            self._logging_error = "Unable to load WireGuard diagnostics settings or open the log."
            logger.warning("%s", self._logging_error)

    async def get_logging_settings(self) -> dict[str, object]:
        return {"success": True, **self._logging, "logging_error": self._logging_error}

    async def set_logging_settings(self, enabled: bool, debug: bool) -> dict[str, object]:
        if not isinstance(enabled, bool) or not isinstance(debug, bool):
            return self._failure(NetworkManagerError("Logging settings must be booleans."))
        settings: LoggingSettings = {"enabled": enabled, "debug": enabled and debug}
        handler = self._log_handler if enabled else None
        try:
            if enabled and handler is None:
                handler = self._open_diagnostic_log()
            self._write_json(self._settings_path("logging.json"), settings, "logging")
        except NetworkManagerError as error:
            if handler is not None and handler is not self._log_handler:
                handler.close()
            return self._failure(error)
        self._configure_logging(settings, handler)
        return await self.get_logging_settings()

    def _log(self, level: int, message: str, *args: object) -> None:
        if self._log_handler is not None:
            self._diagnostics.log(level, "session=%s " + message, self._log_session, *args)

    def _profile_ref(self, uuid: str) -> str:
        return f"tunnel-{self._profile_refs.setdefault(uuid, len(self._profile_refs) + 1)}"

    def _peer_ref(self, uuid: str, peer: str) -> str:
        refs = self._peer_refs.setdefault(uuid, {})
        return f"{self._profile_ref(uuid)}-peer-{refs.setdefault(peer, len(refs) + 1)}"

    def _observe_resume(self) -> None:
        if self._log_handler is None or not hasattr(time, "CLOCK_BOOTTIME"):
            return
        # BOOTTIME includes suspend; monotonic time (used for verification) does not.
        suspended = time.clock_gettime(time.CLOCK_BOOTTIME) - time.monotonic()
        if self._suspended_time is None or suspended - self._suspended_time >= 1:
            if self._suspended_time is not None:
                self._log(logging.INFO, "resume_detected suspended_seconds=%.0f",
                          suspended - self._suspended_time)
                self._debug_samples.clear()
            self._suspended_time = suspended

    async def _debug_peer_snapshot(self, profile: Profile) -> None:
        handler = self._log_handler
        if handler is None or not self._logging["debug"] or profile["state"] != "connected":
            return
        uuid, device = profile["uuid"], profile["device"]
        if not device:
            return
        now = time.monotonic()
        if uuid in self._debug_samples and now - self._debug_samples[uuid] < PROBE_INTERVAL:
            return
        self._debug_samples[uuid] = now
        try:
            handshakes, counters, endpoints = await asyncio.wait_for(
                asyncio.gather(
                    _handshakes(device), _transfer_counters(device), _endpoints(device),
                    return_exceptions=True,
                ),
                timeout=2,
            )
        except TimeoutError:
            self._log(logging.DEBUG, "%s peer_snapshot_timed_out", self._profile_ref(uuid))
            return
        if handler is not self._log_handler or not self._logging["debug"]:
            return
        if not isinstance(handshakes, dict) or not isinstance(counters, dict) or not isinstance(endpoints, dict):
            for kind, sample in zip(("handshakes", "counters", "endpoints"), (handshakes, counters, endpoints)):
                if isinstance(sample, NetworkManagerError):
                    self._log(logging.DEBUG, "%s peer_snapshot_unavailable source=%s",
                              self._profile_ref(uuid), kind)
                elif isinstance(sample, BaseException):
                    raise sample
            return
        previous_endpoints, previous_counters = self._peer_samples.get(uuid, ({}, {}))
        self._peer_samples[uuid] = (endpoints, counters)
        peers = handshakes.keys() | counters.keys() | endpoints.keys()
        if not peers:
            self._log(logging.DEBUG, "%s no_peers", self._profile_ref(uuid))
        for peer in sorted(peers):
            endpoint = endpoints.get(peer)
            timestamp = handshakes.get(peer)
            age = max(0, int(time.time()) - timestamp) if timestamp else "never"
            changes = [
                "increased" if current > old else "reset" if current < old else "unchanged"
                for current, old in zip(counters[peer], previous_counters[peer])
            ] if peer in counters and peer in previous_counters else ["baseline", "baseline"]
            self._log(
                logging.DEBUG, "%s handshake_age_seconds=%s rx=%s tx=%s endpoint=%s endpoint_changed=%s",
                self._peer_ref(uuid, peer), age, *changes,
                "none" if endpoint in (None, "(none)") else "ipv6" if endpoint.startswith("[") else "ipv4",
                peer in previous_endpoints and endpoint != previous_endpoints[peer],
            )

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

    async def _advanced_properties(self, uuid: str) -> list[dict[str, str]]:
        output = await _nmcli("--fields", "all", "connection", "show", "uuid", uuid)
        properties: list[dict[str, str]] = []
        for line in output.splitlines():
            fields = _split_fields(line)
            if len(fields) != 2 or not fields[0].islower():
                continue
            key, value = fields
            if "." in key and key not in STRUCTURED_PROPERTIES | IDENTITY_PROPERTIES:
                properties.append({"key": key, "value": value})
        return properties

    async def get_connection_config(self, uuid: str) -> dict[str, object]:
        try:
            async with self._lock:
                profile = await self._profile(uuid)
                _, settings = await _nm_connection(profile["uuid"])
                return {
                    "success": True,
                    "config": _wireguard_config(settings),
                    "advanced": await self._advanced_properties(profile["uuid"]),
                }
        except NetworkManagerError as error:
            return self._failure(error)

    async def read_conf_file(self, path: str) -> dict[str, object]:
        try:
            if (
                not isinstance(path, str) or not Path(path).is_absolute()
                or Path(path).suffix.lower() != ".conf"
            ):
                raise NetworkManagerError("Select a WireGuard .conf file.")
            # Nonblocking open also lets us reject pipes/devices without waiting on them.
            descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as source:
                if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                    raise NetworkManagerError("Select a regular .conf file.")
                content = source.read(1024 * 1024 + 1)
            if len(content) > 1024 * 1024:
                raise NetworkManagerError("Configuration files must be at most 1 MiB.")
            return {"success": True, "text": content.decode("utf-8-sig")}
        except NetworkManagerError as error:
            return self._failure(error)
        except (OSError, UnicodeError, ValueError):
            # File contents, names and decoding errors can contain private keys.
            return self._failure(NetworkManagerError(
                "Unable to import configuration. Select a readable UTF-8 .conf file "
                "of at most 1 MiB."
            ))

    async def create_connection_config(
        self, config: dict[str, object], advanced: list[dict[str, str]],
    ) -> dict[str, object]:
        return await self.set_connection_config(None, config, advanced)

    async def _create_connection_config(
        self, config: dict[str, object], advanced: list[dict[str, str]],
    ) -> dict[str, object]:
        uuid = str(uuid4())
        settings = {
            "connection": {
                "id": _variant("s", ""), "uuid": _variant("s", uuid),
                "type": _variant("s", "wireguard"), "autoconnect": _variant("b", False),
                "interface-name": _variant("s", f"wg-{uuid.replace('-', '')[:12]}"),
            },
            "ipv4": {"method": _variant("s", "disabled")},
            "ipv6": {"method": _variant("s", "disabled")},
        }
        _apply_wireguard_config(settings, config, advanced)
        reply = await _busctl(
            NM_SETTINGS_PATH, "org.freedesktop.NetworkManager.Settings", "AddConnectionUnsaved",
            "a{sa{sv}}", *_encode_bus_value("a{sa{sv}}", settings),
        )
        path = reply[0] if len(reply) == 1 else None
        if not isinstance(path, str) or not path.startswith("/"):
            raise NetworkManagerError("NetworkManager returned an unexpected connection path.")
        try:
            if advanced:
                arguments = ["connection", "modify", "--temporary", "uuid", uuid]
                for update in advanced:
                    arguments.extend((update["key"], update["value"]))
                await _nmcli(*arguments)
                _, settings = await _nm_connection(uuid)
            await _nm_update(path, settings)
        except (NetworkManagerError, asyncio.CancelledError):
            try:
                await _busctl(path, NM_CONNECTION_INTERFACE, "Delete")
            except NetworkManagerError as cleanup:
                raise NetworkManagerError(
                    "Saving failed and the new profile could not be removed. "
                    "Refresh the connection list before retrying."
                ) from cleanup
            raise
        return {"success": True, "uuid": uuid}

    async def set_connection_config(
        self, uuid: str | None, config: dict[str, object], advanced: list[dict[str, str]],
    ) -> dict[str, object]:
        if not _config_input(config):
            return self._failure(NetworkManagerError("Invalid WireGuard configuration."))
        if not isinstance(advanced, list) or any(
            not isinstance(update, dict)
            or set(update) != {"key", "value"}
            or not isinstance(update["key"], str)
            or not isinstance(update["value"], str)
            for update in advanced
        ):
            return self._failure(NetworkManagerError("Advanced properties must be key/value pairs."))
        keys = [update["key"] for update in advanced]
        if IDENTITY_PROPERTIES.intersection(keys):
            return self._failure(NetworkManagerError(
                "A connection's UUID and type are managed by NetworkManager "
                "and cannot be overridden."
            ))
        if "connection.autoconnect" in keys:
            return self._failure(NetworkManagerError(
                "connection.autoconnect is managed by the startup controls."
            ))
        if structured_keys := STRUCTURED_PROPERTIES.intersection(keys):
            return self._failure(NetworkManagerError(
                f"{min(structured_keys)} is edited in the "
                "WireGuard fields above, not as an advanced property."
            ))
        if (
            len(advanced) > 512
            or len(set(keys)) != len(keys)
            or any(
                len(key) > 128
                or not key[0:1].islower()
                or any(not (character.isascii() and (character.isalnum() or character in ".-"))
                       for character in key)
                or "." not in key
                for key in keys
            )
            or any(
                len(update["value"]) > 16384 or "\0" in update["value"] for update in advanced
            )
        ):
            return self._failure(NetworkManagerError("Invalid or duplicate advanced property."))
        try:
            _validate_advanced_names(keys)
            advanced = [
                {**update, "value": str(_number(
                    update["value"], "Firewall mark", 2**32 - 1, off=True, hexadecimal=True,
                ))} if update["key"] == "wireguard.fwmark" else update
                for update in advanced
            ]
            async with self._lock:
                if uuid is None:
                    return await self._create_connection_config(config, advanced)
                profile = await self._profile(uuid)
                path, settings = await _nm_connection(profile["uuid"])
                # Validate before nmcli so invalid fields cannot leave a partial save.
                changed = _apply_wireguard_config(settings, config, advanced)
                if advanced:
                    arguments = ["connection", "modify", "uuid", profile["uuid"]]
                    for update in advanced:
                        arguments.extend((update["key"], update["value"]))
                    await _nmcli(*arguments)
                    if changed:
                        path, settings = await _nm_connection(profile["uuid"])
                        changed = _apply_wireguard_config(settings, config)
                if changed:
                    await _nm_update(path, settings)
                return {"success": True}
        except NetworkManagerError as error:
            return self._failure(error)

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
            logger.warning("Steam readiness unavailable.")
        self._observe_resume()
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
            if self._log_handler is not None:
                source = "requested" if pending else (
                    "observed_connecting" if activation.since is not None else "already_active"
                )
                self._log(logging.INFO, "%s activation_observed source=%s", self._profile_ref(uuid), source)
        if activation.completed:
            if profile["state"] == "connected":
                await self._probe_activation(profile, activation)
            return "established"
        if profile["state"] == "connected":
            if not profile["device"]:
                raise NetworkManagerError("NetworkManager did not report a WireGuard interface.")
            handshakes = await _handshakes(profile["device"])
            if activation.baseline is None:
                activation.baseline = handshakes
            verified_peer = next((
                peer for peer, timestamp in handshakes.items()
                if timestamp > 0 and (
                    timestamp >= activation.since if activation.since is not None
                    else timestamp > activation.baseline.get(peer, 0)
                )
            ), None)
            if verified_peer is not None:
                activation.completed = True
                if self._log_handler is not None:
                    self._log(logging.INFO, "%s verified evidence=handshake", self._peer_ref(uuid, verified_peer))
                return "established"
            received = await _received_bytes(profile["device"])
            if activation.received is not None:
                verified_peer = next((
                    peer for peer, amount in received.items()
                    if peer in activation.received and amount > activation.received[peer]
                ), None)
                if verified_peer is not None:
                    activation.completed = True
                    if self._log_handler is not None:
                        self._log(logging.INFO, "%s verified evidence=receive", self._peer_ref(uuid, verified_peer))
                    return "established"
            activation.received = received
            await self._probe_activation(profile, activation)
        return "timeout" if time.monotonic() - activation.started >= HANDSHAKE_TIMEOUT else "waiting"

    async def _probe_activation(self, profile: Profile, activation: Activation) -> None:
        if activation.last_probe is not None and (
            time.monotonic() - activation.last_probe < PROBE_INTERVAL
        ):
            return
        if not profile["device"]:
            raise NetworkManagerError("NetworkManager did not report a WireGuard interface.")
        uuid = profile["uuid"]
        stage = "targets"
        try:
            if activation.targets is None:
                activation.targets = await _probe_targets(profile["device"])
            stage = "send"
            failures = await _send_probe(profile["device"], activation.targets)
        except NetworkManagerError:
            if self._log_handler is not None:
                self._log(logging.DEBUG, "%s probe_failed stage=%s", self._profile_ref(uuid), stage)
            raise
        if self._log_handler is not None:
            self._log(logging.DEBUG, "%s probe_round targets=%d send_failures=%s",
                      self._profile_ref(uuid), len(activation.targets), failures)
        activation.last_probe = time.monotonic()

    def _failure(self, error: Exception) -> dict[str, object]:
        logger.warning("WireGuard request failed; details returned to the caller.")
        return {"success": False, "error": str(error)}

    async def get_profiles(self) -> dict[str, object]:
        try:
            async with self._lock:
                self._observe_resume()
                profiles = await self._profiles()
                for uuid in self._activations.keys() - self._active_paths.keys():
                    del self._activations[uuid]
                for uuid in self._pending_activations.keys() - self._active_paths.keys():
                    del self._pending_activations[uuid]
                for uuid in self._logged_statuses.keys() - self._active_paths.keys():
                    self._log(logging.INFO, "%s profile_removed", self._profile_ref(uuid))
                    del self._logged_statuses[uuid]
                    self._debug_samples.pop(uuid, None)
                    self._peer_samples.pop(uuid, None)
                statuses: list[dict[str, object]] = []
                for profile in profiles:
                    error_message = None
                    activation = self._activations.get(profile["uuid"])
                    previous_probe = activation.last_probe if activation else None
                    try:
                        handshake = await self._handshake_status(profile)
                    except NetworkManagerError as error:
                        logger.warning("WireGuard verification unavailable; details returned to the caller.")
                        handshake = "unknown"
                        error_message = str(error)
                    status: dict[str, object] = {
                        **profile, "handshake": handshake, "handshake_error": error_message,
                    }
                    activation = self._activations.get(profile["uuid"])
                    status["probe_sent"] = (
                        activation.last_probe if activation and activation.last_probe != previous_probe
                        else None
                    )
                    if self._log_handler is not None:
                        uuid = profile["uuid"]
                        reference = self._profile_ref(uuid)
                        status["diagnostic_ref"] = reference
                        current = (profile["state"], handshake)
                        if self._logged_statuses.get(uuid) != current:
                            self._log(logging.INFO, "%s state=%s verification=%s", reference, *current)
                            self._logged_statuses[uuid] = current
                        await self._debug_peer_snapshot(profile)
                    statuses.append(status)
                result: dict[str, object] = {"success": True, "profiles": statuses}
                if self._startup_error is not None:
                    result["startup_error"] = self._startup_error
                return result
        except NetworkManagerError as error:
            self._log(logging.INFO, "profile_query_failed")
            return self._failure(error)

    async def get_peer_health(self, uuid: str) -> dict[str, object]:
        try:
            async with self._lock:
                profile = await self._profile(uuid)
                if profile["state"] != "connected":
                    return {"success": True, "peers": []}
                if not profile["device"]:
                    raise NetworkManagerError("NetworkManager did not report a WireGuard interface.")
                handshakes = await _handshakes(profile["device"])
                counters = await _transfer_counters(profile["device"])
                endpoints = await _endpoints(profile["device"])
                peers: list[dict[str, object]] = []
                for peer in sorted(handshakes.keys() | counters.keys()):
                    entry: dict[str, object] = {
                        "public_key": peer,
                        "endpoint_ip": _endpoint_ip(endpoints.get(peer)),
                        "last_handshake": handshakes.get(peer) or None,
                        "received_bytes": counters.get(peer, (0, 0))[0],
                        "sent_bytes": counters.get(peer, (0, 0))[1],
                    }
                    if self._log_handler is not None:
                        entry["diagnostic_ref"] = self._peer_ref(uuid, peer)
                    peers.append(entry)
                return {"success": True, "peers": peers}
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
        action = "up" if connected else "down"
        if self._log_handler is not None:
            self._log(logging.INFO, "%s connection_requested action=%s", self._profile_ref(uuid), action)
        try:
            await _nmcli("connection", action, "uuid", uuid, wait=30)
        except NetworkManagerError:
            if self._log_handler is not None:
                self._log(logging.INFO, "%s connection_failed action=%s", self._profile_ref(uuid), action)
            raise
        if not connected:
            self._activations.pop(uuid, None)
            self._pending_activations.pop(uuid, None)

    async def _main(self) -> None:
        logger.info("WireGuard plugin loaded.")
        self._load_logging()
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
                    raise NetworkManagerError(f"Smart connect unavailable: system state is {state!r}.")
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
                        message = f"Smart connect failed for {uuid}: {error}"
                        logger.warning("WireGuard Smart connect profile activation failed.")
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
            logger.warning("WireGuard Smart connect startup failed.")
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
        self._log(logging.INFO, "backend_unloaded")
        if self._log_handler is not None:
            self._diagnostics.removeHandler(self._log_handler)
            self._log_handler.close()
            self._log_handler = None
        logger.info("WireGuard plugin unloaded; existing connections are unchanged.")
