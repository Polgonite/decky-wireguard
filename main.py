import asyncio
import logging
import os
import time
from dataclasses import dataclass
from typing import Literal, TypedDict
from uuid import UUID


logger = logging.getLogger("decky-wireguard")

State = Literal["connected", "connecting", "disconnecting", "disconnected", "unknown"]
HandshakeState = Literal["inactive", "waiting", "established", "timeout", "unknown"]
HANDSHAKE_TIMEOUT = 30


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
