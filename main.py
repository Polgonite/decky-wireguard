import asyncio
import logging
import os
from typing import Literal, TypedDict
from uuid import UUID


logger = logging.getLogger("decky-wireguard")

State = Literal["connected", "connecting", "disconnecting", "disconnected", "unknown"]


class Profile(TypedDict):
    uuid: str
    name: str
    device: str
    state: State


class NetworkManagerError(Exception):
    pass


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


async def _nmcli(*arguments: str, wait: int = 10) -> str:
    try:
        process = await asyncio.create_subprocess_exec(
            "nmcli",
            "--terse",
            "--escape",
            "yes",
            "--colors",
            "no",
            "--wait",
            str(wait),
            *arguments,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        )
    except FileNotFoundError as error:
        raise NetworkManagerError(
            "nmcli is not installed. This plugin requires NetworkManager and nmcli."
        ) from error
    except OSError as error:
        raise NetworkManagerError(f"Unable to start nmcli: {error}") from error

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
            "NetworkManager timed out. The operation may still finish; refresh its status."
        ) from error

    if process.returncode != 0:
        detail = (stderr or stdout).decode("utf-8", errors="replace").strip()
        raise NetworkManagerError(
            f"nmcli failed ({process.returncode}): {detail[:600] or 'No error details.'}"
        )
    return stdout.decode("utf-8", errors="replace")


class Plugin:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()

    async def _profiles(self) -> list[Profile]:
        output = await _nmcli(
            "--fields", "UUID,TYPE,NAME,DEVICE,STATE", "connection", "show"
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
        for line in output.split("\n"):
            if not line:
                continue
            fields = _split_fields(line)
            if len(fields) != 5:
                raise NetworkManagerError("NetworkManager returned unexpected profile data.")
            uuid, kind, name, device, state = fields
            if kind != "wireguard":
                continue
            profiles.append({
                "uuid": uuid,
                "name": name,
                "device": "" if device == "--" else device,
                "state": states.get(state, "unknown"),
            })
        return sorted(profiles, key=lambda profile: (profile["name"].casefold(), profile["uuid"]))

    def _failure(self, error: Exception) -> dict[str, object]:
        logger.warning("%s", error)
        return {"success": False, "error": str(error)}

    async def get_profiles(self) -> dict[str, object]:
        try:
            async with self._lock:
                return {"success": True, "profiles": await self._profiles()}
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
                await _nmcli(
                    "connection", "up" if connected else "down", "uuid", canonical_uuid, wait=30
                )
                return {"success": True}
        except NetworkManagerError as error:
            return self._failure(error)

    async def _main(self) -> None:
        logger.info("WireGuard plugin loaded.")

    async def _unload(self) -> None:
        logger.info("WireGuard plugin unloaded; existing connections are unchanged.")
