import asyncio
import base64
import copy
import json
import logging
import os
import pwd
import re
import socket
import struct
import tempfile
import time
from contextlib import asynccontextmanager
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
from urllib.parse import unquote_to_bytes
from uuid import UUID, uuid4

logger = logging.getLogger("decky-wireguard")

State = Literal["connected", "connecting", "disconnecting", "disconnected", "unknown"]
HandshakeState = Literal["inactive", "waiting", "established", "timeout", "unknown"]
HANDSHAKE_TIMEOUT = 30
PROBE_INTERVAL = 5
DEBUG_SAMPLE_INTERVAL = 10
Address = IPv4Address | IPv6Address
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
STEAM_READINESS_MAX_AGE = 10
DIAGNOSTIC_LOG = "wireguard-diagnostics.log"
NM_SERVICE = "org.freedesktop.NetworkManager"
NM_SETTINGS_PATH = "/org/freedesktop/NetworkManager/Settings"
NM_CONNECTION_INTERFACE = "org.freedesktop.NetworkManager.Settings.Connection"
DBUS_SERVICE = "org.freedesktop.DBus"
DBUS_SYSTEM_SOCKET = "/run/dbus/system_bus_socket"
DBUS_TIMEOUT = 15
EDITOR_SNAPSHOT_TTL = 30 * 60
NM_UPDATE_TO_DISK = 0x01
NM_UPDATE_NO_REAPPLY = 0x40
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
DIRECT_PROPERTIES = frozenset({"ipv4.method", "ipv6.method", "connection.interface-name", "wireguard.fwmark"})
# Only these non-secret properties may be passed as arguments to offline nmcli.
OFFLINE_PROPERTIES = frozenset({
    "connection.zone", "connection.metered", "connection.autoconnect-priority",
    "wireguard.peer-routes", "wireguard.ip4-auto-default-route", "wireguard.ip6-auto-default-route",
    "ipv6.addr-gen-mode", "ipv6.ip6-privacy",
    *(f"{family}.{field}" for family in ("ipv4", "ipv6") for field in (
        "gateway", "routes", "routing-rules", "route-table", "route-metric", "never-default",
        "dns-priority", "dns-options", "ignore-auto-dns", "ignore-auto-routes", "may-fail",
    )),
})
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
    include_prereleases: bool
    auto_update_check: bool


def _default_ui_settings() -> UISettings:
    # Update checks contact GitHub, so they stay opt-in.
    return {"show_advanced_settings": False, "include_prereleases": False, "auto_update_check": False}


class Profile(TypedDict):
    uuid: str
    name: str
    device: str
    state: State


class NetworkManagerError(Exception):
    pass


class UnconfirmedWrite(NetworkManagerError):
    pass


class ProfileConflict(NetworkManagerError):
    pass


class DuplicateUuid(NetworkManagerError):
    pass


@dataclass(frozen=True)
class ProfileRef:
    owner: str
    path: str
    bus_id: str

    def revision_token(self, version: int) -> str:
        return f"{self.bus_id}|{self.owner}|{self.path}|{version}"


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


async def _command(executable: str, *arguments: str, wait: int = 10, input_data: bytes | None = None,
                   desktop_user: pwd.struct_passwd | None = None) -> str:
    credentials = {}
    if desktop_user is not None and os.geteuid() == 0:
        credentials = {"user": desktop_user.pw_uid, "group": desktop_user.pw_gid,
                       "extra_groups": os.getgrouplist(desktop_user.pw_name, desktop_user.pw_gid)}
    try:
        process = await asyncio.create_subprocess_exec(
            executable,
            *arguments,
            stdin=asyncio.subprocess.DEVNULL if input_data is None else asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={"LC_ALL": "C"} if desktop_user else {**os.environ, "LC_ALL": "C", "LANG": "C"},
            **credentials,
        )
    except FileNotFoundError as error:
        if desktop_user:
            raise NetworkManagerError("Import requires the system Python interpreter at /usr/bin/python3.") from error
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
        stdout, stderr = await asyncio.wait_for(process.communicate(input_data), timeout=wait + 5)
    except (TimeoutError, asyncio.TimeoutError, asyncio.CancelledError) as error:
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
        if desktop_user:
            raise NetworkManagerError("Unable to import. Select a user-readable, regular UTF-8 .conf file of at most 1 MiB.")
        if input_data is not None:
            # Neither stream is safe to echo when nmcli is processing a private keyfile.
            raise NetworkManagerError("NetworkManager rejected the offline advanced settings.")
        detail = (stderr or stdout).decode("utf-8", errors="replace").strip()
        raise NetworkManagerError(
            f"{executable} failed ({process.returncode}): {detail[:600] or 'No error details.'}"
        )
    return stdout.decode("utf-8", errors="replace")


async def _nmcli(*arguments: str, wait: int = 10, escape: bool = True) -> str:
    return await _command(
        "nmcli", "--terse", "--escape", "yes" if escape else "no", "--colors", "no", "--wait", str(wait),
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


def _dbus_alignment(signature: str) -> int:
    if not signature:
        raise ValueError("Missing D-Bus type")
    code = signature[0]
    if code in "yvg":
        return 1
    if code in "nq":
        return 2
    if code in "biuso":
        return 4
    if code in "xtd({":
        return 8
    if code == "a":
        return 4
    raise ValueError(f"Unsupported D-Bus type {code!r}")


def _dbus_pad(buffer: bytearray, alignment: int) -> None:
    buffer.extend(b"\0" * (-len(buffer) % alignment))


def _dbus_signature_bytes(signature: str) -> bytes:
    encoded = signature.encode("ascii")
    if len(encoded) > 255:
        raise ValueError("D-Bus signature is too long")
    return bytes((len(encoded),)) + encoded + b"\0"


def _dbus_encode_value(buffer: bytearray, signature: str, value: object) -> None:
    _dbus_pad(buffer, _dbus_alignment(signature))
    code = signature[0]
    if code == "a":
        element = signature[1:]
        length_offset = len(buffer)
        buffer.extend(b"\0\0\0\0")
        _dbus_pad(buffer, _dbus_alignment(element))
        start = len(buffer)
        if element.startswith("{"):
            if not isinstance(value, dict):
                raise TypeError("Expected a D-Bus dictionary")
            for key, item in value.items():
                _dbus_encode_value(buffer, element, (key, item))
        else:
            if not isinstance(value, list):
                raise TypeError("Expected a D-Bus array")
            for item in value:
                _dbus_encode_value(buffer, element, item)
        struct.pack_into("<I", buffer, length_offset, len(buffer) - start)
        return
    if code == "{":
        _dbus_pad(buffer, 8)
        key_type, value_type = _split_signature(signature[1:-1])
        if not isinstance(value, (tuple, list)) or len(value) != 2:
            raise TypeError("Expected a D-Bus dictionary entry")
        _dbus_encode_value(buffer, key_type, value[0])
        _dbus_encode_value(buffer, value_type, value[1])
        return
    if code == "(":
        types = _split_signature(signature[1:-1])
        if not isinstance(value, (tuple, list)) or len(value) != len(types):
            raise TypeError("Expected a D-Bus struct")
        for kind, item in zip(types, value):
            _dbus_encode_value(buffer, kind, item)
        return
    if code == "v":
        if (
            not isinstance(value, dict) or set(value) != {"type", "data"}
            or not isinstance(value["type"], str)
            or len(_split_signature(value["type"])) != 1
        ):
            raise TypeError("Expected a D-Bus variant")
        buffer.extend(_dbus_signature_bytes(value["type"]))
        _dbus_encode_value(buffer, value["type"], value["data"])
        return
    if code in "so":
        if not isinstance(value, str):
            raise TypeError("Expected a D-Bus string")
        encoded = value.encode("utf-8")
        buffer.extend(struct.pack("<I", len(encoded)))
        buffer.extend(encoded)
        buffer.append(0)
        return
    if code == "g":
        if not isinstance(value, str):
            raise TypeError("Expected a D-Bus signature")
        buffer.extend(_dbus_signature_bytes(value))
        return
    if code == "b":
        if not isinstance(value, bool):
            raise TypeError("Expected a D-Bus boolean")
        buffer.extend(struct.pack("<I", value))
        return
    if code == "d":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError("Expected a D-Bus double")
        buffer.extend(struct.pack("<d", value))
        return
    if code in "ynqiuxt":
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("Expected a D-Bus integer")
        format_code = {"y": "B", "n": "h", "q": "H", "u": "I", "x": "q", "t": "Q"}.get(
            code, code,
        )
        try:
            buffer.extend(struct.pack("<" + format_code, value))
        except struct.error as error:
            raise ValueError("D-Bus integer is out of range") from error
        return
    raise ValueError(f"Unsupported D-Bus type {code!r}")


def _dbus_encode(signature: str, values: list[object]) -> bytes:
    types = _split_signature(signature)
    if len(values) != len(types):
        raise ValueError("D-Bus argument count does not match its signature")
    body = bytearray()
    for kind, value in zip(types, values):
        _dbus_encode_value(body, kind, value)
    return bytes(body)


class _DBusReader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def _align(self, alignment: int) -> None:
        self.offset += -self.offset % alignment
        if self.offset > len(self.data):
            raise ValueError("Truncated D-Bus value")

    def _read(self, length: int) -> bytes:
        end = self.offset + length
        if end > len(self.data):
            raise ValueError("Truncated D-Bus value")
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def _signature(self) -> str:
        length = self._read(1)[0]
        try:
            value = self._read(length).decode("ascii")
        except UnicodeError as error:
            raise ValueError("Invalid D-Bus signature") from error
        if self._read(1) != b"\0":
            raise ValueError("Invalid D-Bus signature terminator")
        return value

    def value(self, signature: str) -> object:
        self._align(_dbus_alignment(signature))
        code = signature[0]
        if code == "a":
            length = struct.unpack("<I", self._read(4))[0]
            element = signature[1:]
            self._align(_dbus_alignment(element))
            end = self.offset + length
            if end > len(self.data):
                raise ValueError("Truncated D-Bus array")
            if element.startswith("{"):
                result: dict[object, object] = {}
                while self.offset < end:
                    key, item = self.value(element)
                    result[key] = item
                if self.offset != end:
                    raise ValueError("Invalid D-Bus array length")
                return result
            result = []
            while self.offset < end:
                result.append(self.value(element))
            if self.offset != end:
                raise ValueError("Invalid D-Bus array length")
            return result
        if code == "{":
            self._align(8)
            key_type, value_type = _split_signature(signature[1:-1])
            return [self.value(key_type), self.value(value_type)]
        if code == "(":
            return [self.value(kind) for kind in _split_signature(signature[1:-1])]
        if code == "v":
            kind = self._signature()
            if len(_split_signature(kind)) != 1:
                raise ValueError("Invalid D-Bus variant signature")
            return {"type": kind, "data": self.value(kind)}
        if code in "so":
            length = struct.unpack("<I", self._read(4))[0]
            try:
                value = self._read(length).decode("utf-8")
            except UnicodeError as error:
                raise ValueError("Invalid D-Bus string") from error
            if self._read(1) != b"\0":
                raise ValueError("Invalid D-Bus string terminator")
            return value
        if code == "g":
            return self._signature()
        if code == "b":
            value = struct.unpack("<I", self._read(4))[0]
            if value not in (0, 1):
                raise ValueError("Invalid D-Bus boolean")
            return bool(value)
        if code == "d":
            return struct.unpack("<d", self._read(8))[0]
        if code in "ynqiuxt":
            format_code = {"y": "B", "n": "h", "q": "H", "u": "I", "x": "q", "t": "Q"}.get(
                code, code,
            )
            return struct.unpack(
                "<" + format_code, self._read(struct.calcsize("<" + format_code)),
            )[0]
        raise ValueError(f"Unsupported D-Bus type {code!r}")


def _dbus_message(
    message_type: int, serial: int, path: str | None = None,
    interface: str | None = None, member: str | None = None,
    destination: str | None = None, signature: str = "",
    values: list[object] | None = None, reply_serial: int | None = None,
    error_name: str | None = None,
) -> bytes:
    fields: list[object] = []
    for field, kind, value in (
        (1, "o", path), (2, "s", interface), (3, "s", member),
        (4, "s", error_name),
        (5, "u", reply_serial), (6, "s", destination), (8, "g", signature),
    ):
        if value is not None and (field != 8 or value):
            fields.append([field, {"type": kind, "data": value}])
    header = bytearray()
    for field in fields:
        _dbus_encode_value(header, "(yv)", field)
    body = _dbus_encode(signature, values or [])
    padding = b"\0" * (-((16 + len(header)) % 8) % 8)
    fixed = struct.pack(
        "<cBBBIII", b"l", message_type, 0, 1, len(body), serial, len(header),
    )
    return fixed + header + padding + body


async def _dbus_read_message(reader: asyncio.StreamReader) -> tuple[int, int, dict[int, object], bytes]:
    fixed = await reader.readexactly(16)
    if fixed[0:1] != b"l" or fixed[3] != 1:
        raise ValueError("Unsupported D-Bus message encoding")
    message_type = fixed[1]
    body_length, serial, fields_length = struct.unpack_from("<III", fixed, 4)
    if fields_length > 1024 * 1024 or body_length > 16 * 1024 * 1024:
        raise ValueError("D-Bus message is too large")
    fields_data = await reader.readexactly(fields_length)
    fields_reader = _DBusReader(fields_data)
    fields: dict[int, object] = {}
    while fields_reader.offset < fields_length:
        field, value = fields_reader.value("(yv)")
        if not isinstance(field, int) or not isinstance(value, dict):
            raise ValueError("Invalid D-Bus header field")
        fields[field] = value["data"]
    await reader.readexactly(-((16 + fields_length) % 8) % 8)
    body = await reader.readexactly(body_length)
    return message_type, serial, fields, body


def _dbus_secrets(values: object) -> set[str]:
    secrets: set[str] = set()
    if isinstance(values, dict):
        for key, value in values.items():
            if key in {"private-key", "preshared-key"} and isinstance(value, dict):
                secret = value.get("data")
                if isinstance(secret, str) and secret:
                    secrets.add(secret)
            secrets.update(_dbus_secrets(value))
    elif isinstance(values, (list, tuple)):
        for value in values:
            secrets.update(_dbus_secrets(value))
    return secrets


def _system_bus_address() -> tuple[bytes, str | None]:
    address = os.environ.get("DBUS_SYSTEM_BUS_ADDRESS")
    if address is None:
        return os.fsencode(DBUS_SYSTEM_SOCKET), None
    # Never fall back to another bus when a configured address isn't supported.
    if not address.startswith("unix:") or ";" in address:
        raise NetworkManagerError("The configured system D-Bus must use a single Unix socket.")
    options = {}
    for part in address[5:].split(","):
        key, sep, value = part.partition("=")
        if not sep or key in options or re.search(r"%(?![a-fA-F0-9]{2})", value):
            raise NetworkManagerError("Invalid system D-Bus socket address.")
        options[key] = value
    guid = options.get("guid")
    if guid is not None and not re.fullmatch("[0-9a-fA-F]{32}", guid):
        raise NetworkManagerError("Invalid system D-Bus server GUID.")
    names = options.keys() - {"guid"}
    if names not in ({"path"}, {"abstract"}):
        raise NetworkManagerError("Unsupported system D-Bus socket address.")
    name = names.pop()
    value = unquote_to_bytes(options[name])
    if not value or b"\0" in value or (name == "path" and not value.startswith(b"/")):
        raise NetworkManagerError("Invalid system D-Bus socket address.")
    return (b"\0" if name == "abstract" else b"") + value, guid


def _verify_bus_peer(writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("socket")
    if peer is None:
        raise NetworkManagerError("Cannot verify the system D-Bus server.")
    credentials = struct.Struct("iII")  # Linux struct ucred
    _, uid, _ = credentials.unpack(peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, credentials.size))
    if uid == 0:
        return
    for account in ("messagebus", "dbus"):
        try:
            if uid == pwd.getpwnam(account).pw_uid:
                return
        except KeyError:
            continue
    raise NetworkManagerError("The system D-Bus socket is not owned by a trusted bus service.")


class _Bus:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader, self.writer = reader, writer
        self.serial = 0
        self._watched_profile: ProfileRef | None = None
        self.profile_updates = 0

    async def watch_profile_updates(self, ref: ProfileRef) -> None:
        rule = (
            f"type='signal',sender='{ref.owner}',path='{ref.path}',"
            f"interface='{NM_CONNECTION_INTERFACE}',member='Updated'"
        )
        await self.call("/org/freedesktop/DBus", DBUS_SERVICE, "AddMatch", "s", rule,
                        destination=DBUS_SERVICE)
        self._watched_profile = ref
        self.profile_updates = 0

    async def call(self, path: str, interface: str, method: str, signature: str = "",
                   *values: object, destination: str = NM_SERVICE) -> list[object]:
        self.serial += 1
        sent = False
        try:
            self.writer.write(_dbus_message(
                1, self.serial, path, interface, method, destination, signature, list(values),
            ))
            sent = True
            return await asyncio.wait_for(self._reply(values), DBUS_TIMEOUT)
        except (asyncio.TimeoutError, OSError, asyncio.IncompleteReadError, ValueError, TypeError, struct.error) as error:
            if sent:
                raise UnconfirmedWrite("No confirmation from NetworkManager. Reload before retrying.") from error
            raise NetworkManagerError("Unable to communicate with NetworkManager over D-Bus.") from error

    async def _reply(self, values: tuple) -> list[object]:
        await self.writer.drain()
        while True:
            message_type, _, fields, body = await _dbus_read_message(self.reader)
            ref = self._watched_profile
            if (message_type == 4 and ref is not None
                    and fields.get(1) == ref.path and fields.get(2) == NM_CONNECTION_INTERFACE
                    and fields.get(3) == "Updated" and fields.get(7) == ref.owner):
                self.profile_updates += 1
            if fields.get(5) != self.serial or message_type not in (2, 3):
                continue
            if message_type == 3:
                error_name = fields.get(4)
                if error_name == NM_SERVICE + ".Settings.VersionIdMismatch":
                    raise ProfileConflict("The profile changed outside this editor. Reload before saving.")
                if error_name == NM_SERVICE + ".Settings.UuidExists":
                    raise DuplicateUuid("A profile with this UUID already exists.")
                if error_name in ("org.freedesktop.DBus.Error.NoReply", "org.freedesktop.DBus.Error.Disconnected"):
                    raise UnconfirmedWrite("No confirmation from NetworkManager. Reload the profile before retrying.")
                detail = ""
                if fields.get(8) == "s":
                    try:
                        detail = _DBusReader(body).value("s")
                    except (UnicodeError, ValueError, struct.error):
                        pass
                if isinstance(detail, str):
                    for secret in _dbus_secrets(values):
                        detail = detail.replace(secret, "[redacted]")
                    detail = detail.strip()[:600]
                error = f" ({error_name})" if isinstance(error_name, str) else ""
                reason = f": {detail}" if detail else ""
                raise NetworkManagerError(
                    f"NetworkManager rejected the connection settings{error}{reason}"
                )
            result_signature = fields.get(8, "")
            if not result_signature:
                return []
            body_reader = _DBusReader(body)
            return [body_reader.value(kind) for kind in _split_signature(result_signature)]


@asynccontextmanager
async def _system_bus():
    writer = None

    async def connect() -> _Bus:
        nonlocal writer
        address, guid = _system_bus_address()
        reader, writer = await asyncio.open_unix_connection(address)
        _verify_bus_peer(writer)
        identity = str(os.getuid()).encode("ascii").hex()
        writer.write(b"\0AUTH EXTERNAL " + identity.encode("ascii") + b"\r\n")
        await writer.drain()
        auth = (await reader.readline()).split()
        if len(auth) != 2 or auth[0] != b"OK" or (guid and auth[1].lower() != guid.lower().encode()):
            raise NetworkManagerError("Unable to authenticate to the system D-Bus.")
        writer.write(b"BEGIN\r\n")
        bus = _Bus(reader, writer)
        hello = await bus.call("/org/freedesktop/DBus", DBUS_SERVICE, "Hello", destination=DBUS_SERVICE)
        if len(hello) != 1 or not isinstance(hello[0], str) or not hello[0].startswith(":"):
            raise NetworkManagerError("Unable to initialize the system D-Bus connection.")
        return bus

    try:
        try:
            bus = await asyncio.wait_for(connect(), DBUS_TIMEOUT)
        except (asyncio.TimeoutError, OSError, ValueError, UnconfirmedWrite) as error:
            raise NetworkManagerError("Unable to initialize the system D-Bus connection.") from error
        yield bus
    finally:
        if writer is not None:
            writer.transport.abort()  # never wait indefinitely for buffered writes on cancellation
            try:
                await writer.wait_closed()
            except OSError:
                pass


async def _dbus_call(
    path: str, interface: str, method: str, signature: str = "",
    *values: object, destination: str = NM_SERVICE,
) -> list[object]:
    async with _system_bus() as bus:
        return await bus.call(path, interface, method, signature, *values, destination=destination)


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


async def _nm_profile_ref(bus: _Bus, uuid: str) -> ProfileRef:
    ids = await bus.call("/org/freedesktop/DBus", DBUS_SERVICE, "GetId", destination=DBUS_SERVICE)
    if len(ids) != 1 or not isinstance(ids[0], str) or not re.fullmatch(r"[0-9a-fA-F]{32}", ids[0]):
        raise NetworkManagerError("Cannot identify the system D-Bus instance.")
    owners = await bus.call("/org/freedesktop/DBus", DBUS_SERVICE, "GetNameOwner", "s",
                            NM_SERVICE, destination=DBUS_SERVICE)
    if (len(owners) != 1 or not isinstance(owners[0], str)
            or not re.fullmatch(r":[\w-]+(?:\.[\w-]+)+", owners[0], re.ASCII)):
        raise NetworkManagerError("Cannot identify the NetworkManager service.")
    owner = owners[0]
    reply = await bus.call(
        NM_SETTINGS_PATH, "org.freedesktop.NetworkManager.Settings",
        "GetConnectionByUuid", "s", uuid, destination=owner,
    )
    path = reply[0] if len(reply) == 1 else None
    if not isinstance(path, str) or not path.startswith("/"):
        raise NetworkManagerError("NetworkManager returned an unexpected connection path.")
    return ProfileRef(owner, path, ids[0])


async def _nm_snapshot(bus: _Bus, ref: ProfileRef) -> tuple[int, Settings]:
    await bus.watch_profile_updates(ref)
    before = await _nm_revision(bus, ref)
    secrets = _settings_reply(await bus.call(
        ref.path, NM_CONNECTION_INTERFACE, "GetSecrets", "s", "wireguard", destination=ref.owner,
    ))
    updates = bus.profile_updates
    revision = await _nm_revision(bus, ref)
    # GetSecrets may itself advance the version, but an Updated signal after
    # its reply means the returned secrets no longer belong to this revision.
    if revision not in (before, before + 1) or bus.profile_updates != updates:
        raise ProfileConflict("The profile changed while reading its keys. Reload before editing.")
    settings = _settings_reply(await bus.call(ref.path, NM_CONNECTION_INTERFACE, "GetSettings", destination=ref.owner))
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
    return revision, settings


async def _nm_revision(bus: _Bus, ref: ProfileRef) -> int:
    reply = await bus.call(
        ref.path, "org.freedesktop.DBus.Properties", "Get", "ss",
        NM_CONNECTION_INTERFACE, "VersionId", destination=ref.owner,
    )
    value = reply[0] if len(reply) == 1 else None
    if (not isinstance(value, dict) or value.get("type") != "t"
            or type(value.get("data")) is not int or value["data"] <= 0):
        raise NetworkManagerError("Cannot safely edit without a NetworkManager profile revision.")
    return value["data"]


def _normalize_ip_settings(settings: Settings) -> None:
    for family in ("ipv4", "ipv6"):
        values = settings.get(family, {})
        for legacy, replacement in (
            ("addresses", "address-data"), ("routes", "route-data"), ("dns", "dns-data"),
        ):
            if replacement in values:
                values.pop(legacy, None)


async def _prepare_settings(settings: Settings, config: dict[str, object], advanced: list[dict[str, str]]) -> bool:
    changed = _apply_wireguard_config(settings, config, advanced)
    _normalize_ip_settings(settings)
    remaining = []
    # These fields already have validated, unambiguous D-Bus representations.
    # In particular nmcli interprets even unprefixed firewall marks as hexadecimal.
    for update in advanced:
        key, value = update["key"], update["value"]
        if key in DIRECT_PROPERTIES:
            group, field = key.split(".")
            settings[group][field] = _variant("u", int(value)) if key == "wireguard.fwmark" else _variant("s", value)
            changed = True
        elif key in OFFLINE_PROPERTIES:
            remaining.append(update)
        else:
            raise NetworkManagerError("Unsupported advanced property. Use a listed non-secret NetworkManager property.")
    if not remaining:
        return changed
    requested = {item["key"]: item["value"].strip() for item in remaining}
    for family in ("ipv4", "ipv6"):
        may_fail = requested.get(f"{family}.may-fail")
        method = _data(settings.get(family, {}), "method", "disabled")
        # nmcli reads many spellings as false (for example 0b0), so accept only known true ones.
        if (
            method in ("disabled", "ignore") and may_fail is not None
            and may_fail.lower() not in ("", "1", "on", "y", "yes", "t", "true")
        ):
            raise NetworkManagerError(
                f"{family}.may-fail cannot be set to {may_fail!r} when {family}.method is {method}; "
                "NetworkManager would discard it."
            )
        never = requested.get(f"{family}.never-default")
        if requested.get(f"{family}.gateway") and never is not None and never.lower() not in (
            "", "0", "no", "n", "false", "f", "off",
        ):
            raise NetworkManagerError(f"Cannot set {family}.gateway together with {family}.never-default enabled.")
    try:
        # Decky adds py_modules to sys.path; a source checkout uses the namespace package.
        try:
            from nm_keyfile import KeyfileCodec
        except ModuleNotFoundError:
            from py_modules.nm_keyfile import KeyfileCodec
        codec = KeyfileCodec()
        blob = _dbus_message(1, 1, "/", NM_CONNECTION_INTERFACE, "Update", NM_SERVICE,
                             "a{sa{sv}}", [settings])
        keyfile = codec.to_keyfile(blob)
        arguments = [arg for update in remaining for arg in (update["key"], update["value"])]
        edited = await _command("nmcli", "--offline", "connection", "modify", *arguments,
                                input_data=keyfile)

        def decode(text: bytes) -> Settings:
            message = codec.from_keyfile(blob, text)
            header_size = struct.unpack_from("<I", message, 12)[0]
            result = _DBusReader(message[(16 + header_size + 7) & ~7:]).value("a{sa{sv}}")
            _normalize_ip_settings(result)
            return result

        before, after = decode(keyfile), decode(edited.encode("utf-8"))
    except (AttributeError, OSError, TypeError, ValueError, struct.error) as error:
        raise NetworkManagerError("Cannot convert advanced settings using the system libnm.") from error
    # Apply only what nmcli changed. A keyfile round trip alone can discard
    # unknown peer options, address attributes or settings from newer daemons.
    allowed = {key.removesuffix(".routes") + ".route-data" if key.endswith(".routes") else key for key in requested}
    for group in before.keys() | after.keys():
        old, new = before.get(group, {}), after.get(group, {})
        for field in old.keys() | new.keys():
            if old.get(field) != new.get(field):
                if f"{group}.{field}" not in allowed:
                    raise NetworkManagerError(
                        f"This edit would also change {group}.{field}. Change that property explicitly."
                    )
                if field in new:
                    settings.setdefault(group, {})[field] = new[field]
                else:
                    settings.get(group, {}).pop(field, None)
    # Older libnm omits some fields from the keyfile (for example a gateway
    # without addresses), so the diff above cannot see their requested removal.
    for key in allowed:
        group, _, field = key.partition(".")
        if field not in after.get(group, {}):
            settings.get(group, {}).pop(field, None)
    _normalize_ip_settings(settings)
    _validate_wireguard_settings(settings, [])
    return True


async def _nm_update(bus: _Bus, ref: ProfileRef, settings: Settings, revision: int) -> None:
    try:
        await bus.call(ref.path, NM_CONNECTION_INTERFACE, "Update2", "a{sa{sv}}ua{sv}",
                       settings, NM_UPDATE_TO_DISK | NM_UPDATE_NO_REAPPLY,
                       {"version-id": _variant("t", revision)}, destination=ref.owner)
    except UnconfirmedWrite:
        if not await _matches_persisted_profile(settings, expected=ref):
            raise


def _comparable_settings(settings: Settings) -> Settings:
    # Normalize only known readback differences. Unknown settings and secrets
    # must still compare exactly, even when the daemon is newer than libnm.
    result = copy.deepcopy(settings)
    _normalize_ip_settings(result)

    def omit_default(values: dict[str, dict[str, object]], key: str, signature: str, default: object) -> None:
        if values.get(key) == _variant(signature, default):
            del values[key]

    if result.get("proxy") == {}:
        del result["proxy"]
    connection = result.get("connection", {})
    connection.pop("timestamp", None)  # last activation, not an editable setting
    omit_default(connection, "permissions", "as", [])
    for key in ("autoconnect-ports", "autoconnect-slaves"):
        omit_default(connection, key, "i", -1)
    for version in (4, 6):
        values = result.get(f"ipv{version}", {})
        if "dns" in values:
            values["dns-data"] = _variant("as", _dns_servers(values, version))
            del values["dns"]
        for key in ("address-data", "route-data"):
            omit_default(values, key, "aa{sv}", [])
        for key in ("dns-search", "dns-data"):
            omit_default(values, key, "as", [])
    wireguard = result.get("wireguard", {})
    for key in ("private-key-flags", "mtu", "listen-port", "fwmark"):
        omit_default(wireguard, key, "u", 0)
    omit_default(wireguard, "peers", "aa{sv}", [])
    for peer in _data(wireguard, "peers", []):
        omit_default(peer, "allowed-ips", "as", [])
        omit_default(peer, "persistent-keepalive", "u", 0)
        omit_default(peer, "preshared-key-flags", "u", SECRET_NOT_REQUIRED)
    return result


async def _matches_persisted_profile(intended: Settings, expected: ProfileRef | None = None) -> bool:
    # Only turn a lost acknowledgement into success with positive evidence.
    try:
        async with _system_bus() as bus:
            ref = await _nm_profile_ref(bus, intended["connection"]["uuid"]["data"])
            if expected is not None and ref != expected:
                return False
            revision, actual = await _nm_snapshot(bus, ref)
            dirty = await bus.call(ref.path, "org.freedesktop.DBus.Properties", "Get", "ss",
                                   NM_CONNECTION_INTERFACE, "Unsaved", destination=ref.owner)
            return (dirty == [_variant("b", False)]
                    and _comparable_settings(actual) == _comparable_settings(intended)
                    and await _nm_revision(bus, ref) == revision)
    except NetworkManagerError:
        return False


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


def _secret_flags(settings: Settings) -> dict[str, object]:
    wireguard = settings.get("wireguard", {})
    return {
        "private_key": _data(wireguard, "private-key-flags", 0),
        "peers": {
            peer["public-key"]["data"]: _data(peer, "preshared-key-flags", SECRET_NOT_REQUIRED)
            for peer in _data(wireguard, "peers", [])
        },
    }


def _check_key_edit(flags: int, label: str) -> None:
    if flags not in (0, SECRET_NOT_REQUIRED):
        raise NetworkManagerError(
            f"{label} cannot be edited here with its current secret-storage policy. "
            "Use NetworkManager's editor."
        )


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
        # Imported peers have no original ID; match their public key to retain stored policy.
        stored = existing.get(original if original is not None else public_key)
        if original not in (None, public_key) and public_key in existing and (
            _data(existing[public_key], "preshared-key-flags", SECRET_NOT_REQUIRED)
            != _data(existing[original], "preshared-key-flags", SECRET_NOT_REQUIRED)
        ):
            raise NetworkManagerError(f"{label} cannot replace a peer with a different secret-storage policy.")
        values = copy.deepcopy(stored) if stored is not None else {}
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
        if stored is None or preshared_key != _data(values, "preshared-key", ""):
            _check_key_edit(_data(values, "preshared-key-flags", SECRET_NOT_REQUIRED), f"{label} preshared key")
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


def _set_search_domains(families: dict[int, dict[str, dict[str, object]]], domains: list[str]) -> None:
    previous = {v: _data(values, "dns-search", []) for v, values in families.items()}
    enabled = {v: set(previous[v]) for v, values in families.items()
               if _data(values, "method", None) not in NO_ADDRESS_METHODS}
    if domains and not enabled:
        raise NetworkManagerError("DNS: search domains need a tunnel address in Address.")
    # The editor flattens both lists. A server or address edit must not reorder
    # either family's search path, even if the two paths overlap.
    unchanged = domains == list(dict.fromkeys(domain for path in previous.values() for domain in path))
    assigned = {v: list(previous[v]) if unchanged and v in enabled else [] for v in families}
    for domain in dict.fromkeys(domains):
        owners = [v for v, path in enabled.items() if domain in path]
        if not owners:
            assigned[next(iter(enabled))].append(domain)
        elif not unchanged:
            for v in owners:
                assigned[v].append(domain)
    for v, values in families.items():
        values["dns-search"] = _variant("as", assigned[v])


def _validate_advanced_names(keys: list[str]) -> None:
    guarded = STRUCTURED_PROPERTIES | IDENTITY_PROPERTIES | DIRECT_PROPERTIES
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
        if key not in OFFLINE_PROPERTIES:
            raise NetworkManagerError("Unsupported advanced property. Use a listed non-secret NetworkManager property.")


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
        _check_key_edit(_data(wireguard, "private-key-flags", 0), "Private key")
        wireguard["private-key"] = _variant("s", private_key)
        wireguard.setdefault("private-key-flags", _variant("u", 0))
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
    if "dns" in changed:
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
    if changed & {"addresses", "dns"}:
        _set_search_domains(families, domains)
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
            fields = _split_fields(line)
            if len(fields) < 2:
                raise ValueError("Missing device field value")
            # nmcli's multiline output can leave IPv6 colons unescaped.
            key, value = fields[0], ":".join(fields[1:])
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
                probe.connect(destination)
                await asyncio.wait_for(asyncio.get_running_loop().sock_sendall(probe, payload), timeout=1)
                sent = True
        except (OSError, asyncio.TimeoutError) as error:
            reason = "send timed out" if isinstance(error, asyncio.TimeoutError) else str(error)
            logger.warning("Tunnel probe send failed (errno=%s).", getattr(error, "errno", None))
            failures.append(f"Unable to send tunnel probe on {device} to {target.address}: {reason}")
    if not sent:
        raise NetworkManagerError("; ".join(failures) or "No tunnel probe targets available.")
    return len(failures)


class Plugin:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._editor_snapshot: tuple[str, Settings] | None = None
        self._editor_expiry: asyncio.TimerHandle | None = None
        self._editor_deadline: float | None = None
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
                return {"success": True, **_default_ui_settings()}
            # Files written before update preferences existed only contain the advanced flag.
            if not isinstance(settings, dict) or not isinstance(settings.get("show_advanced_settings"), bool):
                raise ValueError("Invalid UI settings")
            defaults = _default_ui_settings()
            if any(not isinstance(settings.get(key, False), bool) for key in defaults):
                raise ValueError("Invalid UI settings")
            return {"success": True, **{key: settings.get(key, value) for key, value in defaults.items()}}
        except (OSError, ValueError, NetworkManagerError) as error:
            return self._failure(NetworkManagerError(f"Unable to read UI settings: {error}"))

    async def set_ui_settings(
        self, show_advanced_settings: bool, include_prereleases: bool, auto_update_check: bool,
    ) -> dict[str, object]:
        if not all(
            isinstance(value, bool)
            for value in (show_advanced_settings, include_prereleases, auto_update_check)
        ):
            return self._failure(NetworkManagerError("UI settings must be booleans."))
        settings: UISettings = {
            "show_advanced_settings": show_advanced_settings,
            "include_prereleases": include_prereleases,
            "auto_update_check": auto_update_check,
        }
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
        self._discard_expired_editor_snapshot()
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
        if uuid in self._debug_samples and now - self._debug_samples[uuid] < DEBUG_SAMPLE_INTERVAL:
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
        except asyncio.TimeoutError:
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
        output = await _nmcli(
            "--mode", "multiline", "--fields", "all", "connection", "show", "uuid", uuid, escape=False,
        )
        properties: list[dict[str, str]] = []
        for line in output.splitlines():
            key, separator, value = line.partition(":")
            if separator and (key in DIRECT_PROPERTIES or key in OFFLINE_PROPERTIES):
                properties.append({"key": key, "value": value})
        return properties

    async def get_connection_config(self, uuid: str) -> dict[str, object]:
        try:
            async with self._lock, _system_bus() as bus:
                profile = await self._profile(uuid)
                ref = await _nm_profile_ref(bus, profile["uuid"])
                revision, settings = await _nm_snapshot(bus, ref)
                if (_data(settings.get("connection", {}), "uuid", None) != profile["uuid"]
                        or _data(settings["connection"], "type", None) != "wireguard"):
                    raise ProfileConflict("The WireGuard profile was replaced. Reload before editing.")
                advanced = await self._advanced_properties(profile["uuid"])
                if await _nm_revision(bus, ref) != revision:
                    raise ProfileConflict("The profile changed while loading. Reload before editing.")
                config = _wireguard_config(settings)
                token = ref.revision_token(revision)
                self._clear_editor_snapshot()
                self._editor_snapshot = token, settings
                self._editor_deadline = time.clock_gettime(time.CLOCK_BOOTTIME) + EDITOR_SNAPSHOT_TTL
                self._check_editor_expiry()
                return {
                    "success": True,
                    "revision": token,
                    "config": config,
                    "advanced": advanced,
                    "secret_flags": _secret_flags(settings),
                }
        except NetworkManagerError as error:
            return self._failure(error)

    def _clear_editor_snapshot(self) -> None:
        self._editor_snapshot = None
        self._editor_deadline = None
        if self._editor_expiry is not None:
            self._editor_expiry.cancel()
            self._editor_expiry = None

    def _discard_expired_editor_snapshot(self) -> None:
        if (self._editor_deadline is not None
                and time.clock_gettime(time.CLOCK_BOOTTIME) >= self._editor_deadline):
            self._clear_editor_snapshot()

    def _check_editor_expiry(self) -> None:
        self._discard_expired_editor_snapshot()
        if self._editor_deadline is not None:
            # A short monotonic timer rechecks BOOTTIME promptly after suspend.
            remaining = self._editor_deadline - time.clock_gettime(time.CLOCK_BOOTTIME)
            self._editor_expiry = asyncio.get_running_loop().call_later(
                max(0, min(1, remaining)), self._check_editor_expiry,
            )

    def _current_editor_snapshot(self, revision: str) -> Settings:
        self._discard_expired_editor_snapshot()
        snapshot = self._editor_snapshot
        if snapshot is None or snapshot[0] != revision:
            raise ProfileConflict("The edit snapshot is no longer current. Reload before saving.")
        return snapshot[1]

    async def read_conf_file(self, path: str) -> dict[str, object]:
        try:
            if (
                not isinstance(path, str) or not Path(path).is_absolute()
                or Path(path).suffix.lower() != ".conf"
            ):
                raise NetworkManagerError("Select a WireGuard .conf file.")
            uid = os.geteuid()
            name = os.environ.get("DECKY_USER")
            if not name and uid == 0:
                raise NetworkManagerError("Cannot identify Decky's desktop user for this import.")
            account = pwd.getpwnam(name) if name else pwd.getpwuid(uid)
            if account.pw_uid == 0 or uid not in (0, account.pw_uid):
                raise NetworkManagerError("Cannot import using the desktop user's privileges.")
            helper = Path(__file__).resolve().parent / "py_modules" / "read_conf.py"
            text = await _command("/usr/bin/python3", "-I", "-S", str(helper), path, desktop_user=account)
            return {"success": True, "text": text}
        except NetworkManagerError as error:
            return self._failure(error)
        except (KeyError, OSError, UnicodeError, ValueError):
            # File contents, names and decoding errors can contain private keys.
            return self._failure(NetworkManagerError(
                "Unable to import configuration. Select a readable UTF-8 .conf file "
                "of at most 1 MiB."
            ))

    async def create_connection_config(
        self, config: dict[str, object], advanced: list[dict[str, str]], request_uuid: str | None = None,
    ) -> dict[str, object]:
        return await self.set_connection_config(None, config, advanced, request_uuid=request_uuid)

    async def _create_connection_config(
        self, config: dict[str, object], advanced: list[dict[str, str]], request_uuid: str | None,
    ) -> dict[str, object]:
        uuid = str(uuid4()) if request_uuid is None else request_uuid
        try:
            if not isinstance(uuid, str) or str(UUID(uuid)) != uuid or UUID(uuid).version != 4:
                raise ValueError
        except ValueError:
            raise NetworkManagerError("Invalid UUID for the new profile.") from None
        settings = {
            "connection": {
                "id": _variant("s", ""), "uuid": _variant("s", uuid),
                "type": _variant("s", "wireguard"), "autoconnect": _variant("b", False),
                "interface-name": _variant("s", f"wg-{uuid.replace('-', '')[:12]}"),
            },
            "ipv4": {"method": _variant("s", "disabled")},
            "ipv6": {"method": _variant("s", "disabled")},
        }
        await _prepare_settings(settings, config, advanced)
        try:
            reply = await _dbus_call(
                NM_SETTINGS_PATH, "org.freedesktop.NetworkManager.Settings", "AddConnection",
                "a{sa{sv}}", settings,
            )
            if len(reply) != 1 or not isinstance(reply[0], str) or not reply[0].startswith("/"):
                raise UnconfirmedWrite("Unexpected reply to profile creation.")
        except (DuplicateUuid, UnconfirmedWrite) as failure:
            if not await _matches_persisted_profile(settings):
                if isinstance(failure, DuplicateUuid):
                    return {**self._failure(failure), "code": "uuid_exists", "uuid": uuid}
                raise NetworkManagerError("Creation was not confirmed. Retry this draft or check the connection list.") from failure
        return {"success": True, "uuid": uuid}

    async def set_connection_config(
        self, uuid: str | None, config: dict[str, object], advanced: list[dict[str, str]],
        revision: str | None = None, request_uuid: str | None = None,
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
                    return await self._create_connection_config(config, advanced, request_uuid)
                if not isinstance(revision, str) or not revision:
                    raise NetworkManagerError("A loaded profile revision is required. Reload before saving.")
                self._current_editor_snapshot(revision)
                async with _system_bus() as bus:
                    profile = await self._profile(uuid)
                    ref = await _nm_profile_ref(bus, profile["uuid"])
                    current = await _nm_revision(bus, ref)
                    if revision != ref.revision_token(current):
                        raise ProfileConflict("The profile changed outside this editor. Reload before saving.")
                    settings = copy.deepcopy(self._current_editor_snapshot(revision))
                    changed = await _prepare_settings(settings, config, advanced)
                    self._current_editor_snapshot(revision)
                    if changed:
                        await _nm_update(bus, ref, settings, current)
                return {"success": True}
        except (ProfileConflict, UnconfirmedWrite) as error:
            return {**self._failure(error), "code": "reload_required"}
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
            if kind in ("wifi", "ethernet", "gsm", "cdma", "bt", "bluetooth") and state == "connected":
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
            if activation.since is not None and activation.last_probe is None:
                # Show the initial probe before accepting an activation's immediate handshake.
                activation.received = await _received_bytes(profile["device"])
                await self._probe_activation(profile, activation)
                return "timeout" if time.monotonic() - activation.started >= HANDSHAKE_TIMEOUT else "waiting"
            verified_peer = next((
                peer for peer, timestamp in handshakes.items()
                if timestamp > 0 and (
                    timestamp >= activation.since if activation.since is not None
                    else timestamp > activation.baseline.get(peer, 0)
                )
            ), None)
            if verified_peer is not None:
                if self._log_handler is not None:
                    self._log(logging.INFO, "%s verified evidence=handshake", self._peer_ref(uuid, verified_peer))
                await self._probe_activation(profile, activation, force=True)
                activation.completed = True
                return "established"
            received = await _received_bytes(profile["device"])
            if activation.received is not None:
                verified_peer = next((
                    peer for peer, amount in received.items()
                    if peer in activation.received and amount > activation.received[peer]
                ), None)
                if verified_peer is not None:
                    if self._log_handler is not None:
                        self._log(logging.INFO, "%s verified evidence=receive", self._peer_ref(uuid, verified_peer))
                    await self._probe_activation(profile, activation, force=True)
                    activation.completed = True
                    return "established"
            activation.received = received
            await self._probe_activation(profile, activation)
        return "timeout" if time.monotonic() - activation.started >= HANDSHAKE_TIMEOUT else "waiting"

    async def _probe_activation(
        self, profile: Profile, activation: Activation, *, force: bool = False,
    ) -> None:
        if not force and activation.last_probe is not None and (
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
        self._clear_editor_snapshot()
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
