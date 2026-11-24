import asyncio
import base64
import copy
import json
import os
import shutil
import socket
import struct
import tempfile
import unittest
from contextlib import asynccontextmanager
from ipaddress import ip_address
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from main import (
    DIAGNOSTIC_LOG,
    DuplicateUuid,
    NetworkManagerError,
    UnconfirmedWrite,
    NM_SETTINGS_PATH,
    Plugin,
    ProfileRef,
    ProbeTarget,
    _Bus,
    _DBusReader,
    _command,
    _dbus_call,
    _dbus_message,
    _dbus_read_message,
    _handshakes,
    _nmcli,
    _nm_profile_ref,
    _nm_update,
    _probe_targets,
    _received_bytes,
    _send_probe,
    _split_signature,
    _system_bus_address,
    _system_bus,
    _transfer_counters,
    _verify_bus_peer,
)

HOME = "11111111-1111-4111-8111-111111111111"
WORK = "22222222-2222-4222-8222-222222222222"
WIFI = "33333333-3333-4333-8333-333333333333"
FIELDS = ("--fields", "UUID,TYPE,NAME,DEVICE,STATE,ACTIVE-PATH", "connection", "show")


class UISettingsTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(patch.dict(os.environ, {"DECKY_PLUGIN_SETTINGS_DIR": directory}))
        self.directory = Path(directory)
        self.path = self.directory / "ui.json"
        self.plugin = Plugin()

    async def test_default_and_persistence_across_plugin_instances(self):
        startup = self.directory / "startup.json"
        startup.write_text('{"after_boot": [], "last_boot_id": null, "requirements": {}}')
        self.assertEqual(await self.plugin.get_ui_settings(), {
            "success": True, "show_advanced_settings": False,
        })
        self.assertFalse(self.path.exists())

        for enabled in (True, False):
            with self.subTest(enabled=enabled):
                self.assertEqual(await self.plugin.set_ui_settings(enabled), {
                    "success": True, "show_advanced_settings": enabled,
                })
                self.assertEqual(await Plugin().get_ui_settings(), {
                    "success": True, "show_advanced_settings": enabled,
                })
                self.assertEqual(json.loads(self.path.read_text()), {"show_advanced_settings": enabled})
        self.assertEqual(
            startup.read_text(), '{"after_boot": [], "last_boot_id": null, "requirements": {}}',
        )

    async def test_invalid_or_unavailable_settings_are_reported(self):
        for content in ('not json', '{}', '{"show_advanced_settings": "true"}', '[]'):
            with self.subTest(content=content), self.assertLogs("decky-wireguard"):
                self.path.write_text(content)
                result = await self.plugin.get_ui_settings()
                self.assertFalse(result["success"])
                self.assertIn("Unable to read UI settings", result["error"])
        with patch.dict(os.environ, {"DECKY_PLUGIN_SETTINGS_DIR": ""}), self.assertLogs("decky-wireguard"):
            result = await self.plugin.get_ui_settings()
            self.assertFalse(result["success"])
            self.assertIn("settings directory is unavailable", result["error"])

    async def test_invalid_or_failed_writes_preserve_the_saved_preference(self):
        await self.plugin.set_ui_settings(True)
        with self.assertLogs("decky-wireguard"):
            self.assertFalse((await self.plugin.set_ui_settings("yes"))["success"])
        with patch("main.os.replace", side_effect=PermissionError("Read-only disk")), self.assertLogs(
            "decky-wireguard",
        ):
            result = await self.plugin.set_ui_settings(False)
        self.assertFalse(result["success"])
        self.assertIn("Unable to save UI settings", result["error"])
        self.assertEqual((await Plugin().get_ui_settings())["show_advanced_settings"], True)
        self.assertEqual(list(self.directory.iterdir()), [self.path])


class StartupTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.settings_path = self.directory / "startup.json"
        self.boot_path = self.directory / "boot-id"
        self.boot_path.write_text(HOME)
        environment = patch.dict(os.environ, {"DECKY_PLUGIN_SETTINGS_DIR": directory.name})
        environment.start()
        self.addCleanup(environment.stop)
        boot = patch("main.BOOT_ID_PATH", self.boot_path)
        boot.start()
        self.addCleanup(boot.stop)
        self.autoconnect = {HOME: True, WORK: False}
        self.states = {HOME: "", WORK: ""}
        self.up_error = None

        async def run(*arguments, **kwargs):
            if arguments == FIELDS:
                return "".join(
                    f"{uuid}:wireguard:VPN:wg0:{state}:/active/1\n"
                    for uuid, state in self.states.items()
                )
            if arguments[:2] == ("--get-values", "connection.autoconnect"):
                return "yes\n" if self.autoconnect[arguments[-1]] else "no\n"
            if arguments[:2] == ("connection", "modify"):
                self.autoconnect[arguments[3]] = arguments[-1] == "yes"
                return ""
            if arguments[:2] == ("connection", "up"):
                if self.up_error is not None:
                    raise self.up_error
                self.states[arguments[-1]] = "activated"
                return ""
            self.fail(f"Unexpected nmcli call: {arguments}")

        nmcli = patch("main._nmcli", new_callable=AsyncMock, side_effect=run)
        self.nmcli = nmcli.start()
        self.addCleanup(nmcli.stop)
        command = patch("main._command", new_callable=AsyncMock, return_value="running\n")
        self.command = command.start()
        self.addCleanup(command.stop)
        self.steam_patcher = patch.object(Plugin, "_steam_login_ready", return_value=True)
        self.steam = self.steam_patcher.start()
        self.addCleanup(self.steam_patcher.stop)
        self.internet_patcher = patch.object(
            Plugin, "_internet_ready", new_callable=AsyncMock, return_value=True,
        )
        self.internet = self.internet_patcher.start()
        self.addCleanup(self.internet_patcher.stop)
        self.plugin = Plugin()

    def settings(self):
        return json.loads(self.settings_path.read_text())

    def activations(self):
        return [
            call for call in self.nmcli.await_args_list
            if call.args[:2] == ("connection", "up")
        ]

    async def test_startup_modes_are_exclusive_and_persist_across_instances(self):
        self.assertEqual(await self.plugin.get_startup_settings(HOME), {
            "success": True, "on_boot": True, "after_boot": False,
            "wait_for_steam": True, "wait_for_internet": True, "waiting": None,
        })
        for mode, on_boot, after_boot in [
            ("after_boot", False, True),
            ("on_boot", True, False),
            ("off", False, False),
        ]:
            with self.subTest(mode=mode):
                self.assertEqual(await self.plugin.set_startup(HOME, mode), {"success": True})
                self.assertEqual(await Plugin().get_startup_settings(HOME), {
                    "success": True, "on_boot": on_boot, "after_boot": after_boot,
                    "wait_for_steam": True, "wait_for_internet": True, "waiting": None,
                })
        self.assertFalse(self.activations())

    async def test_invalid_inputs_and_non_wireguard_profiles_are_rejected(self):
        for uuid, mode in [
            (HOME, "invalid"), ("--help", "off"), (None, "off"), (WIFI, "after_boot"),
        ]:
            with self.subTest(uuid=uuid, mode=mode), self.assertLogs("decky-wireguard"):
                self.assertFalse((await self.plugin.set_startup(uuid, mode))["success"])
        self.assertTrue(all(call.args == FIELDS for call in self.nmcli.await_args_list))

    async def test_failed_nmcli_edit_cannot_enable_plugin_mode(self):
        self.nmcli.side_effect = [
            f"{HOME}:wireguard:VPN:::\n", NetworkManagerError("Permission denied"),
        ]
        with self.assertLogs("decky-wireguard"):
            result = await self.plugin.set_startup(HOME, "after_boot")
        self.assertEqual(result, {"success": False, "error": "Permission denied"})
        self.assertFalse(self.settings_path.exists())

    async def test_failed_switch_to_networkmanager_disables_plugin_first(self):
        await self.plugin.set_startup(HOME, "after_boot")
        self.nmcli.side_effect = [
            f"{HOME}:wireguard:VPN:::\n", NetworkManagerError("Permission denied"),
        ]
        with self.assertLogs("decky-wireguard"):
            self.assertFalse((await self.plugin.set_startup(HOME, "on_boot"))["success"])
        self.assertEqual(self.settings()["after_boot"], [])
        self.assertFalse(self.autoconnect[HOME])

    async def test_failed_file_replace_leaves_both_modes_off_and_cleans_temporary_file(self):
        with patch("main.os.replace", side_effect=PermissionError("Read-only disk")), self.assertLogs(
            "decky-wireguard",
        ):
            result = await self.plugin.set_startup(HOME, "after_boot")
        self.assertFalse(result["success"])
        self.assertIn("Unable to save startup settings", result["error"])
        self.assertFalse(self.autoconnect[HOME])
        self.assertEqual(list(self.directory.iterdir()), [self.boot_path])

    async def test_startup_query_reports_unrecognized_networkmanager_output(self):
        self.nmcli.side_effect = [f"{HOME}:wireguard:VPN:::\n", "unexpected\n"]
        with self.assertLogs("decky-wireguard"):
            result = await self.plugin.get_startup_settings(HOME)
        self.assertFalse(result["success"])
        self.assertIn("unexpected autoconnect data", result["error"])

    async def test_once_per_boot_even_after_disconnect_and_backend_restart(self):
        await self.plugin.set_startup(HOME, "after_boot")
        await self.plugin._main()
        await self.plugin._startup_task
        self.assertEqual(len(self.activations()), 1)
        self.assertEqual(self.activations()[0].args, ("connection", "up", "uuid", HOME))
        self.assertEqual(self.activations()[0].kwargs, {"wait": 30})
        await self.plugin._unload()
        self.states[HOME] = ""
        await Plugin()._activate_after_boot()
        self.assertEqual(len(self.activations()), 1)
        self.boot_path.write_text(WORK)
        await Plugin()._activate_after_boot()
        self.assertEqual(len(self.activations()), 2)

    async def test_enabling_after_first_load_waits_until_next_boot(self):
        await self.plugin._activate_after_boot()
        await self.plugin.set_startup(HOME, "after_boot")
        await Plugin()._activate_after_boot()
        self.assertFalse(self.activations())
        self.boot_path.write_text(WORK)
        await Plugin()._activate_after_boot()
        self.assertEqual(len(self.activations()), 1)

    async def test_waits_until_system_boot_finishes_including_degraded_boot(self):
        await self.plugin.set_startup(HOME, "after_boot")
        self.command.side_effect = ["initializing\n", "starting\n", "degraded\n"]

        async def sleeping(_):
            self.assertFalse(self.activations())

        with patch("main.asyncio.sleep", side_effect=sleeping) as sleep:
            await self.plugin._activate_after_boot()
        self.assertEqual(sleep.await_count, 2)
        self.assertEqual(len(self.activations()), 1)
        self.command.assert_awaited_with("systemctl", "show", "--property=SystemState", "--value")

    async def test_setting_disabled_while_waiting_does_not_activate(self):
        await self.plugin.set_startup(HOME, "after_boot")
        self.command.side_effect = ["starting\n", "running\n"]

        async def sleeping(_):
            await self.plugin.set_startup(HOME, "off")

        with patch("main.asyncio.sleep", side_effect=sleeping):
            await self.plugin._activate_after_boot()
        self.assertFalse(self.activations())

    async def test_offline_failure_is_reported_without_retrying_on_reload(self):
        await self.plugin.set_startup(HOME, "after_boot")
        self.up_error = NetworkManagerError("Endpoint DNS unavailable")
        with self.assertLogs("decky-wireguard"):
            await self.plugin._activate_after_boot()
        self.assertIn("Endpoint DNS unavailable", (await self.plugin.get_profiles())["startup_error"])
        await Plugin()._activate_after_boot()
        self.assertEqual(len(self.activations()), 1)

    async def test_failure_does_not_skip_other_configured_tunnels(self):
        await self.plugin.set_startup(HOME, "after_boot")
        await self.plugin.set_startup(WORK, "after_boot")
        self.states.pop(HOME)
        with self.assertLogs("decky-wireguard"):
            await self.plugin._activate_after_boot()
        self.assertEqual([call.args[-1] for call in self.activations()], [WORK])

    async def test_external_autoconnect_conflict_does_not_activate(self):
        await self.plugin.set_startup(HOME, "after_boot")
        self.autoconnect[HOME] = True
        with self.assertLogs("decky-wireguard"):
            await self.plugin._activate_after_boot()
        self.assertFalse(self.activations())
        self.assertIn("resolve the conflict", self.plugin._startup_error)

    async def test_active_or_activating_tunnels_are_left_alone(self):
        await self.plugin.set_startup(HOME, "after_boot")
        await self.plugin.set_startup(WORK, "after_boot")
        self.states.update({HOME: "activated", WORK: "activating"})
        await self.plugin._activate_after_boot()
        self.assertFalse(self.activations())

    async def test_unreadable_or_invalid_boot_id_fails_closed(self):
        await self.plugin.set_startup(HOME, "after_boot")
        for value in ["invalid", None]:
            with self.subTest(value=value), self.assertLogs("decky-wireguard"):
                if value is None:
                    self.boot_path.unlink()
                else:
                    self.boot_path.write_text(value)
                await self.plugin._activate_after_boot()
        self.assertFalse(self.activations())
        self.assertIsNone(self.settings()["last_boot_id"])

    async def test_settings_errors_are_reported_and_do_not_change_networkmanager(self):
        for contents in ["{", '{"after_boot": ["invalid"]}', '{"after_boot": true}']:
            with self.subTest(contents=contents), self.assertLogs("decky-wireguard"):
                self.settings_path.write_text(contents)
                self.assertFalse((await self.plugin.set_startup(HOME, "after_boot"))["success"])
        self.assertTrue(all(call.args == FIELDS for call in self.nmcli.await_args_list))

    async def test_failed_save_does_not_start_automatic_connection(self):
        await self.plugin.set_startup(HOME, "after_boot")
        with patch.object(
            self.plugin, "_write_settings", side_effect=NetworkManagerError("Read-only disk"),
        ), self.assertLogs("decky-wireguard"):
            await self.plugin._activate_after_boot()
        self.assertFalse(self.activations())
        self.command.assert_not_awaited()

    async def test_unloading_cancels_pending_startup_and_does_not_retry_this_boot(self):
        await self.plugin.set_startup(HOME, "after_boot")
        waiting = asyncio.Event()

        async def system_state(*args):
            waiting.set()
            await asyncio.Event().wait()

        self.command.side_effect = system_state
        await self.plugin._main()
        await asyncio.wait_for(waiting.wait(), timeout=1)
        await self.plugin._unload()
        self.assertTrue(self.plugin._startup_task.cancelled())
        await Plugin()._activate_after_boot()
        self.assertFalse(self.activations())

    async def test_legacy_settings_enable_both_requirements_and_preserve_boot_guard(self):
        self.settings_path.write_text(json.dumps({"after_boot": [HOME], "last_boot_id": HOME}))
        result = await self.plugin.get_startup_settings(HOME)
        self.assertTrue(result["wait_for_steam"])
        self.assertTrue(result["wait_for_internet"])
        await self.plugin._activate_after_boot()
        self.assertFalse(self.activations())

    async def test_requirements_persist_independently_per_connection_without_activation(self):
        self.assertEqual(
            await self.plugin.set_startup_requirements(HOME, False, True), {"success": True},
        )
        self.assertEqual(
            await self.plugin.set_startup_requirements(WORK, True, False), {"success": True},
        )
        for uuid, steam, internet in [(HOME, False, True), (WORK, True, False)]:
            result = await Plugin().get_startup_settings(uuid)
            self.assertEqual(result["wait_for_steam"], steam)
            self.assertEqual(result["wait_for_internet"], internet)
        self.assertFalse(self.activations())
        self.assertTrue(self.autoconnect[HOME])

    async def test_requirements_survive_startup_mode_changes(self):
        for steam, internet in [(False, True), (True, False), (False, False)]:
            await self.plugin.set_startup_requirements(HOME, steam, internet)
            for mode in ["after_boot", "off", "after_boot", "on_boot", "after_boot"]:
                with self.subTest(steam=steam, internet=internet, mode=mode):
                    self.assertEqual(await self.plugin.set_startup(HOME, mode), {"success": True})
                    result = await Plugin().get_startup_settings(HOME)
                    self.assertTrue(result["success"])
                    self.assertEqual(result["wait_for_steam"], steam)
                    self.assertEqual(result["wait_for_internet"], internet)

    async def test_invalid_requirements_do_not_write_or_modify_networkmanager(self):
        for uuid, steam, internet in [
            (HOME, "yes", True), (HOME, True, 1), (WIFI, False, False), ("--help", True, True),
        ]:
            with self.subTest(uuid=uuid, steam=steam), self.assertLogs("decky-wireguard"):
                result = await self.plugin.set_startup_requirements(uuid, steam, internet)
                self.assertFalse(result["success"])
        self.assertFalse(self.settings_path.exists())
        self.assertTrue(all(call.args == FIELDS for call in self.nmcli.await_args_list))

    async def test_steam_gate_waits_without_blocking_a_different_connection(self):
        await self.plugin.set_startup(HOME, "after_boot")
        await self.plugin.set_startup(WORK, "after_boot")
        await self.plugin.set_startup_requirements(WORK, False, True)
        self.steam.return_value = False

        async def sleeping(_):
            self.assertEqual([call.args[-1] for call in self.activations()], [WORK])
            status = await self.plugin.get_startup_settings(HOME)
            self.assertIn("Waiting for Steam", status["waiting"])
            self.steam.return_value = True

        with patch("main.asyncio.sleep", side_effect=sleeping):
            await self.plugin._activate_after_boot()
        self.assertEqual([call.args[-1] for call in self.activations()], [WORK, HOME])
        self.assertIsNone((await self.plugin.get_startup_settings(HOME))["waiting"])

    async def test_internet_gate_waits_until_connectivity_returns(self):
        await self.plugin.set_startup(HOME, "after_boot")
        self.internet.return_value = False

        async def sleeping(_):
            self.assertFalse(self.activations())
            self.assertIn("Waiting for internet", self.plugin._startup_waiting[HOME])
            self.internet.return_value = True

        with patch("main.asyncio.sleep", side_effect=sleeping) as sleep:
            await self.plugin._activate_after_boot()
        self.assertEqual(sleep.await_count, 1)
        self.assertEqual(len(self.activations()), 1)

    async def test_disabling_both_requirements_bypasses_only_readiness_checks(self):
        await self.plugin.set_startup(HOME, "after_boot")
        await self.plugin.set_startup_requirements(HOME, False, False)
        self.steam.return_value = False
        self.internet.return_value = False
        await self.plugin._activate_after_boot()
        self.assertEqual(len(self.activations()), 1)
        self.steam.assert_not_called()
        self.internet.assert_not_awaited()
        self.command.assert_awaited_once()

    async def test_requirement_changes_apply_while_waiting(self):
        await self.plugin.set_startup(HOME, "after_boot")
        self.steam.return_value = False

        async def sleeping(_):
            self.assertFalse(self.activations())
            await self.plugin.set_startup_requirements(HOME, False, False)

        with patch("main.asyncio.sleep", side_effect=sleeping):
            await self.plugin._activate_after_boot()
        self.assertEqual(len(self.activations()), 1)

    async def test_manual_disconnect_cancels_pending_startup_even_when_already_disconnected(self):
        await self.plugin.set_startup(HOME, "after_boot")
        self.steam.return_value = False

        async def sleeping(_):
            self.assertEqual(await self.plugin.set_connection(HOME, False), {"success": True})
            self.steam.return_value = True

        with patch("main.asyncio.sleep", side_effect=sleeping):
            await self.plugin._activate_after_boot()
        self.assertFalse(self.activations())

    async def test_disabling_startup_while_waiting_cancels_activation(self):
        await self.plugin.set_startup(HOME, "after_boot")
        self.internet.return_value = False

        async def sleeping(_):
            await self.plugin.set_startup(HOME, "off")
            self.internet.return_value = True

        with patch("main.asyncio.sleep", side_effect=sleeping):
            await self.plugin._activate_after_boot()
        self.assertFalse(self.activations())

    async def test_readiness_failure_is_reported_without_activating_or_reloading_retry(self):
        await self.plugin.set_startup(HOME, "after_boot")
        self.internet.side_effect = NetworkManagerError("Connectivity checking is disabled")
        with self.assertLogs("decky-wireguard"):
            await self.plugin._activate_after_boot()
        await Plugin()._activate_after_boot()
        self.assertFalse(self.activations())
        self.assertIn("Connectivity checking is disabled", self.plugin._startup_error)

    async def test_steam_readiness_fails_closed_on_missing_stale_or_failed_reports(self):
        self.steam_patcher.stop()
        self.assertFalse(self.plugin._steam_login_ready())
        with patch("main.time.monotonic", return_value=100) as clock:
            self.assertEqual(await self.plugin.set_steam_readiness(True), {"success": True})
            self.assertTrue(self.plugin._steam_login_ready())
            clock.return_value = 110
            self.assertFalse(self.plugin._steam_login_ready())
            with self.assertLogs("decky-wireguard"):
                await self.plugin.set_steam_readiness(True, "Steam API unavailable")
            self.assertFalse(self.plugin._steam_login_ready())
            await self.plugin.set_steam_readiness(True)
            self.assertTrue(self.plugin._steam_login_ready())
            await self.plugin.set_steam_readiness(False)
            self.assertFalse(self.plugin._steam_login_ready())

    async def test_invalid_steam_report_is_logged_and_rejected(self):
        for ready, error in [("yes", None), (True, 123)]:
            with self.subTest(ready=ready), self.assertLogs("decky-wireguard"):
                self.assertFalse((await self.plugin.set_steam_readiness(ready, error))["success"])
        self.assertIsNone(self.plugin._steam_reported_at)

    async def test_steam_readiness_rechecked_after_slow_internet_check(self):
        await self.plugin.set_startup(HOME, "after_boot")
        self.steam.side_effect = [True, False, True, True]

        async def sleeping(_):
            self.assertFalse(self.activations())

        with patch("main.asyncio.sleep", side_effect=sleeping) as sleep:
            await self.plugin._activate_after_boot()
        self.assertEqual(sleep.await_count, 1)
        self.assertEqual(len(self.activations()), 1)

    async def test_invalid_requirement_settings_are_not_silently_defaulted(self):
        for requirements in [[], {HOME: {"wait_for_steam": "yes", "wait_for_internet": True}}]:
            with self.subTest(requirements=requirements), self.assertLogs("decky-wireguard"):
                self.settings_path.write_text(json.dumps({
                    "after_boot": [HOME], "last_boot_id": None, "requirements": requirements,
                }))
                self.assertFalse((await self.plugin.get_startup_settings(HOME))["success"])


class InternetReadinessTests(unittest.IsolatedAsyncioTestCase):
    async def test_only_connected_physical_uplink_with_verified_internet_passes(self):
        for output, ready in [
            ("wifi:connected:full:none\n", True),
            ("ethernet:connected:none:full\n", True),
            ("gsm:connected:full:none\n", True),
            ("wireguard:connected:full:full\nwifi:connected:limited:none\n", False),
            ("tun:connected:full:full\n", False),
            ("wifi:disconnected:full:full\n", False),
            ("wifi:connected:portal:none\n", False),
            ("wifi:connected:unknown:none\n", False),
            ("", False),
        ]:
            with self.subTest(output=output), patch(
                "main._command", new_callable=AsyncMock, return_value="b true\nb true\n",
            ), patch("main._nmcli", new_callable=AsyncMock, side_effect=["full\n", output]) as nmcli:
                self.assertEqual(await Plugin()._internet_ready(), ready)
                self.assertEqual(nmcli.await_args_list[0].args, ("networking", "connectivity", "check"))
                self.assertEqual(nmcli.await_args_list[1].args, (
                    "--fields", "TYPE,STATE,IP4-CONNECTIVITY,IP6-CONNECTIVITY", "device", "status",
                ))

    async def test_no_internet_and_captive_portals_do_not_pass(self):
        for state in ["none", "unknown", "limited", "portal"]:
            with self.subTest(state=state), patch(
                "main._command", new_callable=AsyncMock, return_value="b true\nb true\n",
            ), patch("main._nmcli", new_callable=AsyncMock, return_value=state) as nmcli:
                self.assertFalse(await Plugin()._internet_ready())
                nmcli.assert_awaited_once()

    async def test_disabled_or_unavailable_connectivity_checks_cannot_infer_readiness(self):
        for output in ["b true\nb false\n", "b false\nb true\n", "unexpected"]:
            with self.subTest(output=output), patch(
                "main._command", new_callable=AsyncMock, return_value=output,
            ), patch("main._nmcli", new_callable=AsyncMock) as nmcli:
                with self.assertRaisesRegex(NetworkManagerError, "available and enabled"):
                    await Plugin()._internet_ready()
                nmcli.assert_not_awaited()

    async def test_malformed_connectivity_data_is_an_error_not_readiness(self):
        for responses in [["unexpected\n"], ["full\n", "broken:row\n"]]:
            with (
                self.subTest(responses=responses),
                patch("main._command", new_callable=AsyncMock, return_value="b true\nb true\n"),
                patch("main._nmcli", new_callable=AsyncMock, side_effect=responses),
                self.assertRaisesRegex(NetworkManagerError, "unexpected"),
            ):
                await Plugin()._internet_ready()


class ProfileTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.plugin = Plugin()
        self.patcher = patch("main._nmcli", new_callable=AsyncMock)
        self.nmcli = self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.handshake_patcher = patch("main._handshakes", new_callable=AsyncMock, return_value={})
        self.handshakes = self.handshake_patcher.start()
        self.addCleanup(self.handshake_patcher.stop)
        self.received_patcher = patch("main._received_bytes", new_callable=AsyncMock, return_value={})
        self.received = self.received_patcher.start()
        self.addCleanup(self.received_patcher.stop)
        self.targets_patcher = patch(
            "main._probe_targets", new_callable=AsyncMock,
            return_value=[ProbeTarget(ip_address("10.0.0.1"))],
        )
        self.targets = self.targets_patcher.start()
        self.addCleanup(self.targets_patcher.stop)
        self.probe_patcher = patch("main._send_probe", new_callable=AsyncMock)
        self.probe = self.probe_patcher.start()
        self.addCleanup(self.probe_patcher.stop)

    async def test_list_filters_types_decodes_names_and_sorts(self):
        self.nmcli.return_value = (
            f"{WORK}:wireguard:Work\\: VPN\\\\Office:wg0:activated:/active/1\n"
            f"{WIFI}:802-11-wireless:Wi-Fi:wlan0:activated:/active/2\n"
            f"{HOME}:wireguard:home:::\n"
        )
        with patch("main.time.monotonic", return_value=100):
            result = await self.plugin.get_profiles()
        self.assertEqual(result, {
            "success": True,
            "profiles": [
                {
                    "uuid": HOME, "name": "home", "device": "", "state": "disconnected",
                    "handshake": "inactive", "handshake_error": None, "probe_sent": None,
                },
                {
                    "uuid": WORK, "name": "Work: VPN\\Office", "device": "wg0", "state": "connected",
                    "handshake": "waiting", "handshake_error": None, "probe_sent": 100,
                },
            ],
        })
        self.nmcli.assert_awaited_once_with(*FIELDS)

    async def test_empty_list_is_success(self):
        self.nmcli.return_value = ""
        self.assertEqual(await self.plugin.get_profiles(), {"success": True, "profiles": []})

    def diagnostic_directory(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(patch.dict(os.environ, {
            "DECKY_PLUGIN_SETTINGS_DIR": directory, "DECKY_PLUGIN_LOG_DIR": directory,
        }))
        self.addAsyncCleanup(self.plugin._unload)
        return Path(directory) / DIAGNOSTIC_LOG

    async def test_diagnostics_default_off_and_persist_without_debug_after_disabling(self):
        log = self.diagnostic_directory()
        self.nmcli.return_value = f"{HOME}:wireguard:Private VPN:private-wg:activated:/active/42\n"
        self.assertFalse((await self.plugin.get_logging_settings())["enabled"])
        await self.handshake_status()
        self.assertFalse(log.exists())

        self.assertTrue((await self.plugin.set_logging_settings(True, True))["debug"])
        reloaded = Plugin()
        self.addAsyncCleanup(reloaded._unload)
        reloaded._load_logging()
        self.assertTrue((await reloaded.get_logging_settings())["debug"])
        await reloaded._unload()

        self.assertFalse((await self.plugin.set_logging_settings(False, True))["debug"])
        before = log.read_text()
        self.handshakes.return_value = {"public-key": 1000}
        self.assertEqual(await self.handshake_status(), "established")
        self.assertEqual(log.read_text(), before)
        reloaded = Plugin()
        reloaded._load_logging()
        self.assertFalse((await reloaded.get_logging_settings())["enabled"])

    async def test_resume_capture_distinguishes_timeout_from_peer_activity_without_raw_values(self):
        log = self.diagnostic_directory()
        self.nmcli.return_value = (
            f"{HOME}:wireguard:Private VPN:private-wg:activated:/active/42\n"
            f"{WORK}:wireguard:Working VPN:working-wg:activated:/active/43\n"
        )
        self.handshakes.return_value = {"public-key": 0}
        self.probe.return_value = 0
        endpoint = "203.0.113.47:51820"
        with (
            patch("main.time.clock_gettime", side_effect=lambda _: asyncio.get_running_loop().time()) as clock,
            patch("main._endpoints", new_callable=AsyncMock, return_value={"public-key": endpoint}) as endpoints,
            patch("main._transfer_counters", new_callable=AsyncMock, return_value={"public-key": (0, 0)}) as counters,
        ):
            await self.plugin.set_logging_settings(True, False)
            await self.handshake_status()
            endpoints.assert_not_awaited()
            self.assertNotIn("probe_round", log.read_text())
            await self.plugin.set_logging_settings(True, True)
            result = await self.plugin.get_profiles()
            self.assertEqual([p["diagnostic_ref"] for p in result["profiles"]], ["tunnel-1", "tunnel-2"])
            await self.handshake_status()
            self.assertEqual(endpoints.await_count, 2)

            clock.side_effect = lambda _: asyncio.get_running_loop().time() + 60
            await self.plugin.set_steam_readiness(True)
            self.plugin._activations[HOME].started -= 31
            self.plugin._activations[HOME].last_probe -= 11
            self.handshakes.side_effect = lambda device: {
                "public-key": 0 if device == "private-wg" else 1000,
            }
            endpoints.return_value = {"public-key": "198.51.100.35:51820"}
            counters.return_value = {"public-key": (32, 64)}
            result = await self.plugin.get_profiles()
            self.assertEqual([p["handshake"] for p in result["profiles"]], ["timeout", "established"])
            self.assertEqual(endpoints.await_count, 4)

            self.handshakes.side_effect = NetworkManagerError(f"Sensitive command error: {endpoint}")
            with self.assertLogs("decky-wireguard") as notices:
                self.assertEqual(await self.handshake_status(), "unknown")
            self.assertNotIn(endpoint, "\n".join(notices.output))

        text = log.read_text()
        self.assertIn("resume_detected suspended_seconds=60", text)
        self.assertIn("tunnel-1 state=connected verification=timeout", text)
        self.assertIn("tunnel-2-peer-1 verified evidence=handshake", text)
        self.assertIn("tunnel-1-peer-1 handshake_age_seconds=never rx=increased tx=increased", text)
        self.assertIn("endpoint=ipv4 endpoint_changed=True", text)
        self.assertIn("tunnel-1 probe_round targets=1 send_failures=0", text)
        for secret in (HOME, WORK, "Private VPN", "Working VPN", "private-wg", "working-wg",
                       "/active/42", "public-key", "10.0.0.1", endpoint, "198.51.100.35", ":51820",
                       "Sensitive command error"):
            self.assertNotIn(secret, text)

    async def test_peer_health_returns_per_peer_handshakes_and_traffic_counters(self):
        self.nmcli.return_value = f"{HOME}:wireguard:Home:wg0:activated:/active/1\n"
        with patch(
            "main._handshakes", new_callable=AsyncMock,
            return_value={"peer1": 1234, "peer2": 0},
        ), patch(
            "main._transfer_counters", new_callable=AsyncMock,
            return_value={"peer1": (2048, 4096), "peer3": (0, 0)},
        ), patch(
            "main._endpoints", new_callable=AsyncMock,
            return_value={"peer1": "198.51.100.7:51820", "peer2": "[2001:db8::1]:51820", "peer3": "(none)"},
        ):
            result = await self.plugin.get_peer_health(HOME)
        self.assertEqual(result, {
            "success": True,
            "peers": [
                {
                    "public_key": "peer1", "endpoint_ip": "198.51.100.7", "last_handshake": 1234,
                    "received_bytes": 2048, "sent_bytes": 4096,
                },
                {
                    "public_key": "peer2", "endpoint_ip": "2001:db8::1", "last_handshake": None,
                    "received_bytes": 0, "sent_bytes": 0,
                },
                {
                    "public_key": "peer3", "endpoint_ip": None, "last_handshake": None,
                    "received_bytes": 0, "sent_bytes": 0,
                },
            ],
        })

    async def test_peer_health_includes_peer_refs_only_while_logging(self):
        self.diagnostic_directory()
        self.nmcli.return_value = f"{HOME}:wireguard:Home:wg0:activated:/active/1\n"
        with patch(
            "main._handshakes", new_callable=AsyncMock, return_value={"peer1": 1, "peer2": 0},
        ), patch("main._transfer_counters", new_callable=AsyncMock, return_value={}), patch(
            "main._endpoints", new_callable=AsyncMock, return_value={},
        ):
            result = await self.plugin.get_peer_health(HOME)
            self.assertNotIn("diagnostic_ref", result["peers"][0])
            await self.plugin.set_logging_settings(True, False)
            result = await self.plugin.get_peer_health(HOME)
        self.assertEqual(
            [peer["diagnostic_ref"] for peer in result["peers"]], ["tunnel-1-peer-1", "tunnel-1-peer-2"],
        )

    async def test_peer_health_does_not_query_interface_when_disconnected(self):
        self.nmcli.return_value = f"{HOME}:wireguard:Home:--:deactivated:--\n"
        with patch("main._handshakes", new_callable=AsyncMock) as handshakes, patch(
            "main._transfer_counters", new_callable=AsyncMock,
        ) as counters:
            self.assertEqual(
                await self.plugin.get_peer_health(HOME), {"success": True, "peers": []},
            )
        handshakes.assert_not_awaited()
        counters.assert_not_awaited()

    async def test_transient_and_unrecognized_states(self):
        for raw, expected in [
            ("activating", "connecting"),
            ("deactivating", "disconnecting"),
            ("deactivated", "disconnected"),
            ("--", "disconnected"),
            ("future-state", "unknown"),
        ]:
            with self.subTest(state=raw):
                self.nmcli.return_value = f"{HOME}:wireguard:Home:--:{raw}:/active/1\n"
                result = await self.plugin.get_profiles()
                self.assertEqual(result["profiles"][0]["state"], expected)
                self.assertEqual(result["profiles"][0]["device"], "")

    async def test_malformed_output_is_not_an_empty_success(self):
        for output in ["broken:row\n", f"{HOME}:wireguard:Home::\\"]:
            with self.subTest(output=output), self.assertLogs("decky-wireguard"):
                self.nmcli.return_value = output
                result = await self.plugin.get_profiles()
                self.assertFalse(result["success"])
                self.assertIn("NetworkManager returned", result["error"])

    async def test_nmcli_error_is_logged_and_returned(self):
        self.nmcli.side_effect = NetworkManagerError("NetworkManager is not running.")
        with self.assertLogs("decky-wireguard"):
            result = await self.plugin.get_profiles()
        self.assertEqual(result, {"success": False, "error": "NetworkManager is not running."})

    async def test_actions_target_uuid_even_with_duplicate_names(self):
        for connected, initial, command in [
            (True, "", "up"), (False, "activated", "down"),
        ]:
            with self.subTest(connected=connected):
                self.nmcli.reset_mock()
                self.nmcli.side_effect = [
                    (
                        f"{HOME}:wireguard:Same name:wg0:{initial}:/active/1\n"
                        f"{WORK}:wireguard:Same name:wg1:activated:/active/2\n"
                    ),
                    "",
                ]
                self.assertEqual(
                    await self.plugin.set_connection(HOME, connected), {"success": True}
                )
                self.assertEqual(self.nmcli.await_count, 2)
                self.nmcli.assert_awaited_with("connection", command, "uuid", HOME, wait=30)

    async def test_rejects_bad_input_without_starting_nmcli(self):
        for uuid, connected in [
            ("--help", True), ("not-a-uuid", False), (None, True), (HOME, "yes"), (HOME, 1),
        ]:
            with self.subTest(uuid=uuid, connected=connected), self.assertLogs("decky-wireguard"):
                result = await self.plugin.set_connection(uuid, connected)
                self.assertFalse(result["success"])
        self.nmcli.assert_not_awaited()

    async def test_rejects_non_wireguard_and_missing_profiles(self):
        self.nmcli.return_value = f"{WIFI}:802-11-wireless:Wi-Fi:wlan0:activated:/active/1\n"
        for uuid in [WIFI, HOME]:
            with self.subTest(uuid=uuid), self.assertLogs("decky-wireguard"):
                result = await self.plugin.set_connection(uuid, False)
                self.assertFalse(result["success"])
                self.assertIn("WireGuard profile not found", result["error"])
        self.assertTrue(all(call.args == FIELDS for call in self.nmcli.await_args_list))

    async def test_already_in_target_state_does_not_mutate(self):
        for connected, state in [(True, "activated"), (False, "")]:
            with self.subTest(connected=connected):
                self.nmcli.reset_mock()
                self.nmcli.return_value = f"{HOME}:wireguard:Home:wg0:{state}:/active/1\n"
                self.assertEqual(
                    await self.plugin.set_connection(HOME, connected), {"success": True}
                )
                self.nmcli.assert_awaited_once_with(*FIELDS)

    async def test_unknown_and_transient_states_cannot_be_changed(self):
        for state in ["activating", "deactivating", "new-state"]:
            with self.subTest(state=state), self.assertLogs("decky-wireguard"):
                self.nmcli.reset_mock()
                self.nmcli.return_value = f"{HOME}:wireguard:Home:wg0:{state}:/active/1\n"
                self.assertFalse((await self.plugin.set_connection(HOME, True))["success"])
                self.nmcli.assert_awaited_once_with(*FIELDS)

    async def test_activation_failure_is_not_reported_as_success(self):
        self.nmcli.side_effect = [
            f"{HOME}:wireguard:Home:::\n",
            NetworkManagerError("Permission denied"),
        ]
        with self.assertLogs("decky-wireguard"):
            result = await self.plugin.set_connection(HOME, True)
        self.assertEqual(result, {"success": False, "error": "Permission denied"})

    async def test_actions_are_serialized_and_recheck_state(self):
        mutation_started = asyncio.Event()
        finish_mutation = asyncio.Event()
        active = False

        async def run(*arguments, **kwargs):
            nonlocal active
            if arguments == FIELDS:
                return f"{HOME}:wireguard:Home:wg0:{'activated' if active else ''}:/active/1\n"
            mutation_started.set()
            await finish_mutation.wait()
            active = True
            return ""

        self.nmcli.side_effect = run
        first = asyncio.create_task(self.plugin.set_connection(HOME, True))
        await asyncio.wait_for(mutation_started.wait(), timeout=1)
        second = asyncio.create_task(self.plugin.set_connection(HOME, True))
        await asyncio.sleep(0)
        self.assertEqual(self.nmcli.await_count, 2)
        finish_mutation.set()
        self.assertEqual(await asyncio.gather(first, second), [{"success": True}] * 2)
        self.assertEqual(self.nmcli.await_count, 3)

    async def handshake_status(self):
        result = await self.plugin.get_profiles()
        self.assertTrue(result["success"])
        return result["profiles"][0]["handshake"]

    async def test_handshake_timeout_boundary_and_late_recovery(self):
        self.nmcli.return_value = f"{HOME}:wireguard:Home:wg0:activated:/active/1\n"
        self.handshakes.return_value = {"peer": 0}
        with patch("main.time.monotonic", return_value=100) as clock:
            self.assertEqual(await self.handshake_status(), "waiting")
            clock.return_value = 129.999
            self.assertEqual(await self.handshake_status(), "waiting")
            clock.return_value = 130
            self.assertEqual(await self.handshake_status(), "timeout")
            self.handshakes.return_value = {"peer": 1000}
            self.assertEqual(await self.handshake_status(), "established")
            clock.return_value = 10000
            self.handshakes.reset_mock()
            self.assertEqual(await self.handshake_status(), "established")
            self.handshakes.assert_not_awaited()

    async def test_existing_handshake_needs_to_advance_and_any_peer_can_succeed(self):
        self.nmcli.return_value = f"{HOME}:wireguard:Home:wg0:activated:/active/1\n"
        self.handshakes.return_value = {"peer1": 900, "peer2": 0}
        self.assertEqual(await self.handshake_status(), "waiting")
        self.assertEqual(await self.handshake_status(), "waiting")
        self.handshakes.return_value = {"peer1": 900, "peer2": 1000}
        self.assertEqual(await self.handshake_status(), "established")

    async def test_local_activation_counts_handshake_during_nmcli_up(self):
        self.nmcli.return_value = f"{HOME}:wireguard:Home:::\n"
        with patch("main.time.monotonic", return_value=100), patch(
            "main.time.time", return_value=1000,
        ):
            self.assertEqual(await self.plugin.set_connection(HOME, True), {"success": True})
        self.nmcli.return_value = f"{HOME}:wireguard:Home:wg0:activated:/active/1\n"
        self.handshakes.return_value = {"peer": 999}
        with patch("main.time.monotonic", return_value=129):
            self.assertEqual(await self.handshake_status(), "waiting")
            self.handshakes.return_value = {"peer": 1000}
            self.assertEqual(await self.handshake_status(), "established")

    async def test_immediate_local_handshake_still_sends_yellow_then_green_probes(self):
        self.nmcli.return_value = f"{HOME}:wireguard:Home:::\n"
        with patch("main.time.monotonic", return_value=100) as clock, patch(
            "main.time.time", return_value=1000,
        ):
            await self.plugin.set_connection(HOME, True)
            self.nmcli.return_value = f"{HOME}:wireguard:Home:wg0:activated:/active/1\n"
            self.handshakes.return_value = {"peer": 1000}
            result = await self.plugin.get_profiles()
            self.assertEqual(result["profiles"][0]["handshake"], "waiting")
            self.assertEqual(result["profiles"][0]["probe_sent"], 100)
            self.assertEqual(self.probe.await_count, 1)
            clock.return_value = 101
            result = await self.plugin.get_profiles()
            self.assertEqual(result["profiles"][0]["handshake"], "established")
            self.assertEqual(result["profiles"][0]["probe_sent"], 101)
            self.assertEqual(self.probe.await_count, 2)
            self.probe.assert_awaited_with("wg0", self.targets.return_value)

    async def test_local_activation_timeout_starts_before_nmcli_up_finishes(self):
        self.nmcli.return_value = f"{HOME}:wireguard:Home:::\n"
        with patch("main.time.monotonic", return_value=100):
            await self.plugin.set_connection(HOME, True)
        self.nmcli.return_value = f"{HOME}:wireguard:Home:wg0:activated:/active/1\n"
        with patch("main.time.monotonic", return_value=130):
            self.assertEqual(await self.handshake_status(), "timeout")

    async def test_external_activation_observed_while_connecting_counts_first_handshake(self):
        self.nmcli.return_value = f"{HOME}:wireguard:Home:--:activating:/active/1\n"
        with patch("main.time.time", return_value=1000):
            self.assertEqual(await self.handshake_status(), "waiting")
        self.handshakes.assert_not_awaited()
        self.nmcli.return_value = f"{HOME}:wireguard:Home:wg0:activated:/active/1\n"
        self.handshakes.return_value = {"peer": 1001}
        self.assertEqual(await self.handshake_status(), "waiting")
        self.assertEqual(await self.handshake_status(), "established")

    async def test_reactivation_between_refreshes_resets_completed_status(self):
        self.nmcli.return_value = f"{HOME}:wireguard:Home:wg0:activated:/active/1\n"
        self.assertEqual(await self.handshake_status(), "waiting")
        self.handshakes.return_value = {"peer": 1000}
        self.assertEqual(await self.handshake_status(), "established")
        self.nmcli.return_value = f"{HOME}:wireguard:Home:wg0:activated:/active/2\n"
        self.assertEqual(await self.handshake_status(), "waiting")
        self.handshakes.return_value = {"peer": 1001}
        self.assertEqual(await self.handshake_status(), "established")
        self.nmcli.return_value = f"{HOME}:wireguard:Home:::\n"
        self.assertEqual(await self.handshake_status(), "inactive")
        self.assertNotIn(HOME, self.plugin._activations)

    async def test_removed_profile_clears_activation_tracking(self):
        self.nmcli.return_value = f"{HOME}:wireguard:Home:wg0:activated:/active/1\n"
        await self.handshake_status()
        self.nmcli.return_value = ""
        await self.plugin.get_profiles()
        self.assertEqual(self.plugin._activations, {})

    async def test_handshake_failure_does_not_hide_other_profiles_or_prevent_disconnect(self):
        self.nmcli.return_value = (
            f"{HOME}:wireguard:Home:wg0:activated:/active/1\n"
            f"{WORK}:wireguard:Work:wg1:activated:/active/2\n"
        )
        self.handshakes.side_effect = [NetworkManagerError("wg unavailable"), {"peer": 0}]
        with self.assertLogs("decky-wireguard"):
            result = await self.plugin.get_profiles()
        self.assertTrue(result["success"])
        home, work = result["profiles"]
        self.assertEqual(home["handshake"], "unknown")
        self.assertEqual(home["handshake_error"], "wg unavailable")
        self.assertEqual(work["handshake"], "waiting")
        self.assertIsNone(work["handshake_error"])
        self.assertEqual(await self.plugin.set_connection(HOME, False), {"success": True})
        self.nmcli.assert_awaited_with("connection", "down", "uuid", HOME, wait=30)

    async def test_unavailable_handshakes_are_not_a_red_timeout_and_can_recover(self):
        self.nmcli.return_value = f"{HOME}:wireguard:Home:wg0:activated:/active/1\n"
        with patch("main.time.monotonic", return_value=100) as clock:
            self.assertEqual(await self.handshake_status(), "waiting")
            clock.return_value = 140
            self.handshakes.side_effect = NetworkManagerError("wg unavailable")
            with self.assertLogs("decky-wireguard"):
                self.assertEqual(await self.handshake_status(), "unknown")
            self.handshakes.side_effect = None
            self.handshakes.return_value = {"peer": 1000}
            result = await self.plugin.get_profiles()
            self.assertEqual(result["profiles"][0]["handshake"], "established")
            self.assertIsNone(result["profiles"][0]["handshake_error"])

    async def test_existing_handshake_is_verified_by_fresh_received_traffic(self):
        self.nmcli.return_value = f"{HOME}:wireguard:Home:wg0:activated:/active/1\n"
        self.handshakes.return_value = {"peer": 900}
        self.received.return_value = {"peer": 1000}
        self.assertEqual(await self.handshake_status(), "waiting")
        self.probe.assert_awaited_once_with("wg0", self.targets.return_value)
        self.assertEqual(await self.handshake_status(), "waiting")
        self.received.return_value = {"peer": 1032}
        self.assertEqual(await self.handshake_status(), "established")
        self.assertEqual(self.probe.await_count, 2)

    async def test_counter_reset_or_new_peer_baseline_is_not_fresh_evidence(self):
        self.nmcli.return_value = f"{HOME}:wireguard:Home:wg0:activated:/active/1\n"
        self.received.return_value = {"peer": 1000}
        self.assertEqual(await self.handshake_status(), "waiting")
        self.received.return_value = {"peer": 10, "new-peer": 10000}
        self.assertEqual(await self.handshake_status(), "waiting")

    async def test_probe_retries_are_throttled_and_sends_alone_do_not_verify(self):
        self.nmcli.return_value = f"{HOME}:wireguard:Home:wg0:activated:/active/1\n"
        with patch("main.time.monotonic", return_value=100) as clock:
            self.assertEqual(await self.handshake_status(), "waiting")
            clock.return_value = 104.999
            self.assertEqual(await self.handshake_status(), "waiting")
            self.assertEqual(self.probe.await_count, 1)
            clock.return_value = 105
            self.assertEqual(await self.handshake_status(), "waiting")
            self.assertEqual(self.probe.await_count, 2)
            clock.return_value = 130
            self.assertEqual(await self.handshake_status(), "timeout")
            self.targets.assert_awaited_once_with("wg0")
            self.received.return_value = {"peer": 0}
            # First observations are baselines, not newly received traffic.
            self.assertEqual(await self.handshake_status(), "timeout")

    async def test_probe_events_continue_after_verification_and_only_report_new_sends(self):
        self.nmcli.return_value = f"{HOME}:wireguard:Home:wg0:activated:/active/1\n"
        with patch("main.time.monotonic", return_value=100) as clock:
            result = await self.plugin.get_profiles()
            self.assertEqual(result["profiles"][0]["probe_sent"], 100)
            self.assertEqual(result["profiles"][0]["handshake"], "waiting")
            clock.return_value = 101
            result = await self.plugin.get_profiles()
            self.assertIsNone(result["profiles"][0]["probe_sent"])
            self.handshakes.return_value = {"peer": 1000}
            result = await self.plugin.get_profiles()
            self.assertEqual(result["profiles"][0]["handshake"], "established")
            self.assertEqual(result["profiles"][0]["probe_sent"], 101)
            self.assertEqual(self.probe.await_count, 2)
            clock.return_value = 105.999
            result = await self.plugin.get_profiles()
            self.assertIsNone(result["profiles"][0]["probe_sent"])
            self.assertEqual(self.probe.await_count, 2)
            clock.return_value = 106
            result = await self.plugin.get_profiles()
            self.assertEqual(result["profiles"][0]["handshake"], "established")
            self.assertEqual(result["profiles"][0]["probe_sent"], 106)
            self.assertEqual(self.probe.await_count, 3)
            result = await self.plugin.get_profiles()
            self.assertIsNone(result["profiles"][0]["probe_sent"])
            self.assertEqual(self.probe.await_count, 3)
            clock.return_value = 120
            self.nmcli.return_value = f"{HOME}:wireguard:Home:::\n"
            result = await self.plugin.get_profiles()
            self.assertIsNone(result["profiles"][0]["probe_sent"])
            self.assertEqual(self.probe.await_count, 3)

    async def test_failed_verified_probe_reports_error_without_a_pulse_and_can_retry(self):
        self.nmcli.return_value = f"{HOME}:wireguard:Home:wg0:activated:/active/1\n"
        with patch("main.time.monotonic", return_value=100) as clock:
            await self.handshake_status()
            self.handshakes.return_value = {"peer": 1000}
            self.assertEqual(await self.handshake_status(), "established")
            clock.return_value = 110
            self.probe.side_effect = NetworkManagerError("Probe blocked")
            with self.assertLogs("decky-wireguard"):
                result = await self.plugin.get_profiles()
            self.assertEqual(result["profiles"][0]["handshake"], "unknown")
            self.assertEqual(result["profiles"][0]["handshake_error"], "Probe blocked")
            self.assertIsNone(result["profiles"][0]["probe_sent"])
            self.probe.side_effect = None
            result = await self.plugin.get_profiles()
            self.assertEqual(result["profiles"][0]["handshake"], "established")
            self.assertEqual(result["profiles"][0]["probe_sent"], 110)

    async def test_failed_verification_followup_retries_before_the_regular_interval(self):
        self.nmcli.return_value = f"{HOME}:wireguard:Home:wg0:activated:/active/1\n"
        with patch("main.time.monotonic", return_value=100) as clock:
            await self.handshake_status()
            clock.return_value = 101
            self.handshakes.return_value = {"peer": 1000}
            self.probe.side_effect = NetworkManagerError("Probe blocked")
            with self.assertLogs("decky-wireguard"):
                result = await self.plugin.get_profiles()
            self.assertEqual(result["profiles"][0]["handshake"], "unknown")
            self.assertEqual(result["profiles"][0]["handshake_error"], "Probe blocked")
            self.assertIsNone(result["profiles"][0]["probe_sent"])
            clock.return_value = 102
            self.probe.side_effect = None
            result = await self.plugin.get_profiles()
            self.assertEqual(result["profiles"][0]["handshake"], "established")
            self.assertEqual(result["profiles"][0]["probe_sent"], 102)
            self.assertEqual(self.probe.await_count, 3)

    async def test_receive_baseline_resets_for_reactivation(self):
        self.nmcli.return_value = f"{HOME}:wireguard:Home:wg0:activated:/active/1\n"
        self.received.return_value = {"peer": 1000}
        await self.handshake_status()
        self.received.return_value = {"peer": 1032}
        self.assertEqual(await self.handshake_status(), "established")
        self.nmcli.return_value = f"{HOME}:wireguard:Home:wg0:activated:/active/2\n"
        self.assertEqual(await self.handshake_status(), "waiting")
        self.assertEqual(self.probe.await_count, 3)
        self.received.return_value = {"peer": 1064}
        self.assertEqual(await self.handshake_status(), "established")

    async def test_probe_failure_reports_unavailable_but_evidence_can_still_recover(self):
        self.nmcli.return_value = f"{HOME}:wireguard:Home:wg0:activated:/active/1\n"
        self.received.return_value = {"peer": 1000}
        self.probe.side_effect = NetworkManagerError("Probe blocked")
        with self.assertLogs("decky-wireguard"):
            result = await self.plugin.get_profiles()
        self.assertEqual(result["profiles"][0]["handshake"], "unknown")
        self.assertEqual(result["profiles"][0]["handshake_error"], "Probe blocked")
        self.received.return_value = {"peer": 1032}
        self.probe.side_effect = None
        self.assertEqual(await self.handshake_status(), "established")


def v(kind, data):
    return {"type": kind, "data": data}


def wg_key(byte):
    return base64.b64encode(bytes([byte]) * 32).decode()


def ipv4_dns(address):
    return struct.unpack("=I", socket.inet_aton(address))[0]


def decode_bus(signature, tokens):
    """Parse busctl call arguments with the grammar of busctl's message_append_cmdline."""
    code = signature[0]
    if code == "a":
        count = int(tokens.pop(0))
        element = signature[1:]
        if element.startswith("{"):
            key_type, value_type = _split_signature(element[1:-1])
            return {
                decode_bus(key_type, tokens): decode_bus(value_type, tokens) for _ in range(count)
            }
        return [decode_bus(element, tokens) for _ in range(count)]
    if code == "(":
        return [decode_bus(kind, tokens) for kind in _split_signature(signature[1:-1])]
    if code == "v":
        kind = tokens.pop(0)
        return v(kind, decode_bus(kind, tokens))
    token = tokens.pop(0)
    if code == "b":
        return {"true": True, "false": False}[token]
    return token if code in "sog" else int(token)


PEER = wg_key(1)
PRIVATE = wg_key(2)
PSK = wg_key(3)
CONNECTION_PATH = "/org/freedesktop/NetworkManager/Settings/7"
REF = ProfileRef(":1.77", CONNECTION_PATH, "a" * 32)
REVISION = REF.revision_token(42)


def bus_writer(uid=0):
    writer = Mock()
    writer.get_extra_info.return_value.getsockopt.return_value = struct.pack("iII", 123, uid, 42)
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()
    return writer


class ConnectionConfigTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.plugin = Plugin()
        self.settings = {
            "connection": {
                "id": v("s", "Home"), "uuid": v("s", HOME), "type": v("s", "wireguard"),
                "interface-name": v("s", "wg0"),
                "autoconnect": v("b", False), "timestamp": v("t", 1700000000),
            },
            "wireguard": {
                "mtu": v("u", 1420), "listen-port": v("u", 0), "private-key-flags": v("u", 0),
                "peers": v("aa{sv}", [{
                    "public-key": v("s", PEER), "endpoint": v("s", "vpn.example.com:51820"),
                    "allowed-ips": v("as", ["0.0.0.0/0", "::/0"]),
                    "persistent-keepalive": v("u", 25), "preshared-key-flags": v("u", 0),
                    "future-option": v("i", -1),
                }]),
            },
            "ipv4": {
                "method": v("s", "manual"),
                "addresses": v("aau", [[ipv4_dns("10.0.0.2"), 32, 0]]),
                "address-data": v("aa{sv}", [{"address": v("s", "10.0.0.2"), "prefix": v("u", 32)}]),
                "dns": v("au", [ipv4_dns("10.0.0.1")]), "dns-search": v("as", []),
                "dns-priority": v("i", 0),
                "routes": v("aau", []), "route-data": v("aa{sv}", [{
                    "dest": v("s", "192.168.50.0"), "prefix": v("u", 24), "table": v("u", 51820),
                }]),
            },
            "ipv6": {
                "method": v("s", "disabled"), "addresses": v("a(ayuay)", []),
                "address-data": v("aa{sv}", []), "dns": v("aay", []), "dns-search": v("as", []),
            },
            "proxy": {},
        }
        self.secrets = {"wireguard": {
            "private-key": v("s", PRIVATE),
            "peers": v("aa{sv}", [{"public-key": v("s", PEER), "preshared-key": v("s", PSK)}]),
        }}
        self.updates = []
        self.calls = []
        self.nmcli_calls = []
        self.revision = 42
        self.secret_bump = 0
        self.bus_id = REF.bus_id

        async def command(executable, *arguments, **kwargs):
            if executable == "nmcli":
                self.assertEqual(arguments[:3], ("--offline", "connection", "modify"))
                self.assertNotIn(PRIVATE, arguments)
                self.assertNotIn(PSK, arguments)
                self.calls.append("offline modify")
                return await _command(executable, *arguments, **kwargs)
            self.fail(f"Unexpected process: {executable}")

        async def dbus_call(path, interface, method, signature="", *values, destination):
            if method == "GetId":
                self.assertEqual(destination, "org.freedesktop.DBus")
                return [self.bus_id]
            if method == "GetNameOwner":
                self.assertEqual((destination, values), ("org.freedesktop.DBus", ("org.freedesktop.NetworkManager",)))
                return [REF.owner]
            self.assertEqual(destination, REF.owner)
            if method == "GetConnectionByUuid":
                self.calls.append(method)
                self.assertEqual((path, signature, values), (NM_SETTINGS_PATH, "s", (HOME,)))
                return [CONNECTION_PATH]
            if method in ("GetSettings", "GetSecrets"):
                self.calls.append(method)
                self.assertEqual(path, REF.path)
                if method == "GetSecrets":
                    self.assertEqual((signature, values), ("s", ("wireguard",)))
                    self.revision += self.secret_bump
                    return [copy.deepcopy(self.secrets)]
                return [copy.deepcopy(self.settings)]
            if method == "Get":
                self.assertEqual((path, interface, signature, values), (
                    CONNECTION_PATH, "org.freedesktop.DBus.Properties", "ss",
                    ("org.freedesktop.NetworkManager.Settings.Connection", "VersionId"),
                ))
                self.calls.append("Get VersionId")
                return [v("t", self.revision)]
            self.assertEqual((path, interface), (
                CONNECTION_PATH, "org.freedesktop.NetworkManager.Settings.Connection",
            ))
            self.assertEqual(signature, "a{sa{sv}}ua{sv}")
            self.calls.append(method)
            self.assertEqual(values[1:], (0x41, {"version-id": v("t", self.revision)}))
            if method == "Update2":
                self.updates.append(copy.deepcopy(values[0]))
                return [{}]
            self.fail(f"Unexpected direct D-Bus call: {method}")

        async def nmcli(*arguments, **kwargs):
            self.nmcli_calls.append(arguments)
            if arguments == FIELDS:
                return f"{HOME}:wireguard:Home:::\n"
            if arguments == ("--fields", "all", "connection", "show", "uuid", HOME):
                return (
                    "GENERAL.NAME:Home\n"
                    "connection.id:Home\n"
                    "connection.autoconnect:no\n"
                    "connection.zone:\n"
                    "wireguard.private-key:<hidden>\n"
                    "wireguard.fwmark:0x0\n"
                    "ipv4.dns-priority:0\n"
                )
            self.fail(f"Unexpected nmcli call: {arguments}")

        self.bus = Mock(call=AsyncMock(side_effect=dbus_call))

        @asynccontextmanager
        async def system_bus():
            yield self.bus

        self.enterContext(patch("main._system_bus", system_bus))
        for target, side_effect in (("main._command", command), ("main._nmcli", nmcli)):
            patcher = patch(target, new_callable=AsyncMock, side_effect=side_effect)
            patcher.start()
            self.addCleanup(patcher.stop)

    async def config(self):
        result = await self.plugin.get_connection_config(HOME)
        self.assertTrue(result["success"], result)
        return result["config"]

    async def test_config_merges_secrets_and_lists_other_properties_as_advanced(self):
        result = await self.plugin.get_connection_config(HOME)
        self.assertEqual(result, {
            "success": True,
            "revision": REVISION,
            "config": {
                "name": "Home", "private_key": PRIVATE, "addresses": "10.0.0.2/32",
                "dns": "10.0.0.1", "mtu": "1420", "listen_port": "",
                "peers": [{
                    "original_public_key": PEER, "public_key": PEER, "preshared_key": PSK,
                    "allowed_ips": "0.0.0.0/0, ::/0", "endpoint": "vpn.example.com:51820",
                    "persistent_keepalive": "25",
                }],
            },
            "advanced": [
                {"key": "connection.zone", "value": ""},
                {"key": "wireguard.fwmark", "value": "0x0"},
                {"key": "ipv4.dns-priority", "value": "0"},
            ],
        })

    async def test_creation_and_update_transmit_keys_only_in_dbus_payload(self):
        settings = copy.deepcopy(self.settings)
        settings["wireguard"]["private-key"] = v("s", PRIVATE)
        settings["wireguard"]["peers"]["data"][0]["preshared-key"] = v("s", PSK)
        streams = []
        for index in range(2):
            reader = asyncio.StreamReader()
            reader.feed_data(
                b"OK test-guid\r\n"
                + _dbus_message(2, 42, signature="s", values=[":1.1"], reply_serial=1)
                + (
                    _dbus_message(2, 43, signature="s", values=[REF.bus_id], reply_serial=2)
                    + _dbus_message(2, 44, signature="s", values=[REF.owner], reply_serial=3)
                    + _dbus_message(2, 45, signature="o", values=[REF.path], reply_serial=4)
                    + _dbus_message(2, 46, signature="a{sv}", values=[{}], reply_serial=5)
                    if index == 0 else
                    _dbus_message(2, 43, signature="o", values=[CONNECTION_PATH], reply_serial=2)
                )
            )
            reader.feed_eof()
            writer = bus_writer()
            streams.append((reader, writer))
        with (
            patch("main._system_bus", new=_system_bus),
            patch("main.asyncio.open_unix_connection", new_callable=AsyncMock,
                  side_effect=streams),
            patch("main.asyncio.create_subprocess_exec", new_callable=AsyncMock) as spawn,
        ):
            async with _system_bus() as bus:
                ref = await _nm_profile_ref(bus, HOME)
                self.assertEqual(ref, REF)
                await _nm_update(bus, ref, settings, 42)
            self.assertEqual(await _dbus_call(
                NM_SETTINGS_PATH, "org.freedesktop.NetworkManager.Settings",
                "AddConnection", "a{sa{sv}}", settings,
            ), [CONNECTION_PATH])

        for expected_method, (_, writer) in zip(("Update2", "AddConnection"), streams):
            request = writer.write.call_args_list[-1].args[0]
            incoming = asyncio.StreamReader()
            incoming.feed_data(request)
            incoming.feed_eof()
            message_type, _, fields, body = await _dbus_read_message(incoming)
            self.assertEqual(message_type, 1)
            self.assertEqual(fields[3], expected_method)
            self.assertEqual(fields[6], REF.owner if expected_method == "Update2" else "org.freedesktop.NetworkManager")
            self.assertEqual(fields[8], "a{sa{sv}}ua{sv}" if expected_method == "Update2" else "a{sa{sv}}")
            decoded = _DBusReader(body).value("a{sa{sv}}")
            self.assertEqual(decoded["wireguard"]["private-key"], v("s", PRIVATE))
            self.assertEqual(
                decoded["wireguard"]["peers"]["data"][0]["preshared-key"], v("s", PSK),
            )
        spawn.assert_not_awaited()

    async def test_unchanged_config_does_not_update_networkmanager(self):
        self.assertEqual(
            await self.plugin.set_connection_config(HOME, await self.config(), [], REVISION), {"success": True},
        )
        self.assertNotIn("Update2", self.calls)

    async def test_structured_update_preserves_unchanged_private_and_preshared_keys(self):
        config = await self.config()
        config["name"] = "Home VPN"
        result = await self.plugin.set_connection_config(HOME, config, [], REVISION)
        self.assertEqual(result, {"success": True})
        self.assertEqual(self.updates[0]["wireguard"]["private-key"], v("s", PRIVATE))
        self.assertEqual(
            self.updates[0]["wireguard"]["peers"]["data"][0]["preshared-key"], v("s", PSK),
        )

    async def test_update_rewrites_changed_fields_and_preserves_everything_else(self):
        original = copy.deepcopy(self.settings)
        config = await self.config()
        config.update({
            "name": "Home VPN", "private_key": wg_key(4), "addresses": "10.0.0.3/24, fd00::3",
            "dns": "10.0.0.1, fd00::1, home.lan", "listen_port": "51820",
        })
        config["peers"][0]["endpoint"] = "[2001:db8::1]:51820"
        config["peers"].append({
            "original_public_key": None, "public_key": wg_key(5), "preshared_key": "",
            "allowed_ips": "10.1.0.5/16", "endpoint": "", "persistent_keepalive": "off",
        })
        self.assertEqual(await self.plugin.set_connection_config(HOME, config, [], REVISION), {"success": True})
        [update] = self.updates
        self.assertEqual(update["connection"], {
            **original["connection"], "id": v("s", "Home VPN"),
        })
        self.assertEqual(update["proxy"], {})
        self.assertEqual(update["wireguard"]["private-key"], v("s", wg_key(4)))
        self.assertEqual(update["wireguard"]["listen-port"], v("u", 51820))
        self.assertEqual(update["wireguard"]["mtu"], v("u", 1420))
        self.assertEqual(update["wireguard"]["peers"], v("aa{sv}", [
            {
                **original["wireguard"]["peers"]["data"][0],
                "endpoint": v("s", "[2001:db8::1]:51820"), "preshared-key": v("s", PSK),
            },
            {
                "public-key": v("s", wg_key(5)), "allowed-ips": v("as", ["10.1.0.0/16"]),
                "persistent-keepalive": v("u", 0), "preshared-key-flags": v("u", 4),
            },
        ]))
        # Deprecated duplicates would make NetworkManager ignore the edited replacements.
        self.assertEqual(update["ipv4"], {
            "method": v("s", "manual"),
            "address-data": v("aa{sv}", [{"address": v("s", "10.0.0.3"), "prefix": v("u", 24)}]),
            "dns": v("au", [ipv4_dns("10.0.0.1")]), "dns-search": v("as", ["home.lan"]),
            "dns-priority": original["ipv4"]["dns-priority"],
            "route-data": original["ipv4"]["route-data"],
        })
        self.assertEqual(update["ipv6"], {
            "method": v("s", "manual"),
            "address-data": v("aa{sv}", [{"address": v("s", "fd00::3"), "prefix": v("u", 128)}]),
            "dns": v("aay", [[0xfd] + [0] * 14 + [1]]), "dns-search": v("as", []),
        })

    async def test_newer_networkmanager_dns_data_replaces_deprecated_dns(self):
        self.settings["ipv4"]["dns-data"] = v("as", ["10.0.0.1#dns.example"])
        config = await self.config()
        self.assertEqual(config["dns"], "10.0.0.1#dns.example")
        config["dns"] = "10.0.0.53"
        await self.plugin.set_connection_config(HOME, config, [], REVISION)
        self.assertEqual(self.updates[0]["ipv4"]["dns-data"], v("as", ["10.0.0.53"]))
        self.assertNotIn("dns", self.updates[0]["ipv4"])

    async def test_removing_addresses_and_preshared_keys_keeps_profiles_valid(self):
        config = await self.config()
        config.update({"addresses": "", "dns": ""})
        config["peers"][0]["preshared_key"] = ""
        await self.plugin.set_connection_config(HOME, config, [], REVISION)
        update = self.updates[0]
        self.assertEqual(update["ipv4"]["method"], v("s", "disabled"))
        self.assertNotIn("preshared-key", update["wireguard"]["peers"]["data"][0])
        self.assertEqual(
            update["wireguard"]["peers"]["data"][0]["preshared-key-flags"], v("u", 4),
        )

    async def test_removing_a_family_moves_its_search_domains(self):
        self.settings["ipv6"].update({
            "method": v("s", "manual"),
            "address-data": v("aa{sv}", [{"address": v("s", "fd00::2"), "prefix": v("u", 128)}]),
            "dns-search": v("as", ["corp.example"]),
        })
        self.settings["ipv4"]["dns-search"] = v("as", ["corp.example"])
        config = await self.config()
        self.assertEqual(config["dns"], "10.0.0.1, corp.example")
        config["addresses"] = "10.0.0.2/32"
        self.assertEqual(await self.plugin.set_connection_config(HOME, config, [], REVISION), {"success": True})
        update = self.updates[0]
        self.assertEqual(update["ipv6"]["method"], v("s", "disabled"))
        self.assertEqual(update["ipv6"]["dns-search"], v("as", []))
        self.assertEqual(update["ipv4"]["dns-search"], v("as", ["corp.example"]))
        self.assertEqual(update["ipv4"]["dns"], v("au", [ipv4_dns("10.0.0.1")]))

    @unittest.skipUnless(shutil.which("nmcli"), "Offline conversion requires NetworkManager")
    async def test_advanced_and_structured_changes_are_persisted_in_one_update(self):
        config = await self.config()
        config["mtu"] = ""
        self.calls.clear()
        self.assertEqual(await self.plugin.set_connection_config(
            HOME, config, [{"key": "ipv4.dns-priority", "value": "-50"}], REVISION,
        ), {"success": True})
        self.assertEqual(self.calls, [
            "GetConnectionByUuid", "Get VersionId", "offline modify", "Update2",
        ])
        self.assertEqual(len(self.updates), 1)
        self.assertEqual(self.updates[0]["ipv4"]["dns-priority"], v("i", -50))
        self.assertEqual(self.updates[0]["wireguard"]["mtu"], v("u", 0))
        self.assertEqual(self.updates[0]["ipv4"]["route-data"], self.settings["ipv4"]["route-data"])
        self.assertNotIn("routes", self.updates[0]["ipv4"])
        self.assertIn("future-option", self.updates[0]["wireguard"]["peers"]["data"][0])

    async def test_setting_manual_method_and_first_address_is_one_valid_edit(self):
        self.settings["ipv6"]["method"] = v("s", "disabled")
        config = await self.config()
        config["addresses"] += ", fd00::1/64"
        result = await self.plugin.set_connection_config(
            HOME, config, [{"key": "ipv6.method", "value": "manual"}], REVISION,
        )
        self.assertTrue(result["success"], result)
        self.assertEqual(self.updates[0]["ipv6"]["method"], v("s", "manual"))
        self.assertEqual(self.updates[0]["ipv6"]["address-data"]["data"][0]["prefix"], v("u", 64))

    @unittest.skipUnless(shutil.which("nmcli"), "Offline conversion requires NetworkManager")
    async def test_last_address_gateway_and_routes_can_be_removed_together(self):
        self.settings["ipv4"]["gateway"] = v("s", "10.0.0.1")
        config = {**await self.config(), "addresses": "", "dns": ""}
        result = await self.plugin.set_connection_config(HOME, config, [
            {"key": "ipv4.gateway", "value": ""}, {"key": "ipv4.routes", "value": ""},
        ], REVISION)
        self.assertTrue(result["success"], result)
        [updated] = self.updates
        self.assertEqual(updated["ipv4"]["method"], v("s", "disabled"))
        self.assertNotIn("gateway", updated["ipv4"])
        self.assertFalse(updated["ipv4"].get("route-data", v("aa{sv}", []))["data"])

    async def test_uncertain_rejected_or_cancelled_update_never_writes_rollback(self):
        config = {**await self.config(), "name": "Changed"}
        for error in (UnconfirmedWrite("Reload before retrying"), NetworkManagerError("Rejected"),
                      asyncio.CancelledError()):
            with self.subTest(error=error), patch("main._nm_update", side_effect=error) as update:
                if isinstance(error, asyncio.CancelledError):
                    with self.assertRaises(asyncio.CancelledError):
                        await self.plugin.set_connection_config(HOME, config, [], REVISION)
                else:
                    with self.assertLogs("decky-wireguard"):
                        result = await self.plugin.set_connection_config(HOME, config, [], REVISION)
                    self.assertFalse(result["success"])
                update.assert_awaited_once()
                self.assertEqual(update.await_args.args[3], self.revision)
                self.assertFalse(self.updates)

    async def test_stale_editor_revision_is_rejected_before_writing(self):
        config = {**await self.config(), "name": "Changed"}
        for token in (None, REF.revision_token(41), ProfileRef(":1.66", REF.path, REF.bus_id).revision_token(42),
                      ProfileRef(REF.owner, REF.path + "1", REF.bus_id).revision_token(42)):
            with self.subTest(token=token), self.assertLogs("decky-wireguard"):
                result = await self.plugin.set_connection_config(HOME, config, [], token)
                self.assertIn("Reload before saving", result["error"])
                self.assertFalse(self.updates)

    async def test_secret_refresh_version_is_the_save_baseline_and_secrets_are_not_reread(self):
        self.secret_bump = 1
        loaded = await self.plugin.get_connection_config(HOME)
        self.assertEqual(loaded["revision"], REF.revision_token(43))
        config = {**loaded["config"], "name": "New name"}
        self.assertEqual(await self.plugin.set_connection_config(HOME, config, [], loaded["revision"]), {"success": True})
        self.assertEqual(self.calls.count("GetSecrets"), 1)
        self.assertEqual(self.updates[0]["wireguard"]["private-key"], v("s", PRIVATE))
        self.revision += 1
        with self.assertLogs("decky-wireguard"):
            result = await self.plugin.set_connection_config(HOME, config, [], loaded["revision"])
        self.assertEqual(result["code"], "reload_required")
        self.assertEqual(len(self.updates), 1)

    async def test_extra_version_change_during_secret_read_prevents_opening_editor(self):
        self.secret_bump = 2
        with self.assertLogs("decky-wireguard"):
            result = await self.plugin.get_connection_config(HOME)
        self.assertFalse(result["success"])
        self.assertIsNone(self.plugin._editor_snapshot)

    async def test_restarted_bus_reusing_owner_path_and_version_cannot_receive_update(self):
        config = {**await self.config(), "name": "New name"}
        self.bus_id = "b" * 32
        with self.assertLogs("decky-wireguard"):
            result = await self.plugin.set_connection_config(HOME, config, [], REVISION)
        self.assertEqual(result["code"], "reload_required")
        self.assertNotIn("Update2", self.calls)

    @unittest.skipUnless(shutil.which("nmcli"), "Offline conversion requires NetworkManager")
    async def test_gateway_edits_cannot_silently_change_default_route_policy(self):
        self.settings["ipv4"]["never-default"] = v("b", True)
        config = await self.config()
        gateway = {"key": "ipv4.gateway", "value": "10.0.0.1"}
        never = {"key": "ipv4.never-default", "value": "yes"}
        for edits in ([gateway], [never, gateway], [gateway, never]):
            with self.subTest(edits=edits), self.assertLogs("decky-wireguard"):
                result = await self.plugin.set_connection_config(HOME, config, edits, REVISION)
            self.assertFalse(result["success"])
            self.assertIn("never-default", result["error"])
        self.assertFalse(self.updates)
        result = await self.plugin.set_connection_config(
            HOME, config, [gateway, {**never, "value": "no"}], REVISION,
        )
        self.assertTrue(result["success"], result)
        self.assertEqual(self.updates[0]["ipv4"]["gateway"], v("s", "10.0.0.1"))

    @unittest.skipUnless(shutil.which("nmcli"), "Offline conversion requires NetworkManager")
    async def test_invalid_offline_property_never_mutates_the_profile(self):
        config = await self.config()
        with self.assertLogs("decky-wireguard"):
            result = await self.plugin.set_connection_config(
                HOME, config, [{"key": "ipv4.dns-priority", "value": "invalid"}], REVISION,
            )
        self.assertFalse(result["success"])
        self.assertFalse(self.updates)

    async def test_invalid_changes_are_rejected_before_anything_is_saved(self):
        cases = [
            ({"private_key": "short"}, "Private key must be a 44-character"),
            ({"addresses": "10.0.0.300"}, "Address: '10.0.0.300'"),
            ({"dns": "fd00::1"}, "IPv6 DNS servers need an IPv6 tunnel address"),
            ({"name": " "}, "Name is required"),
            ({"mtu": "-1"}, "MTU must be a whole number"),
            ({"peers": "endpoint"}, "Invalid WireGuard configuration"),
            ({"peers": [{"endpoint": "vpn.example.com"}]}, "Peer 1 must be host:port"),
            ({"peers": [{"endpoint": "2001:db8::1:51820"}]}, "Peer 1 must be host:port"),
            ({"peers": [{"allowed_ips": "10.0.0.0/33"}]}, "Peer 1 allowed IPs"),
            ({"peers": [{"original_public_key": wg_key(9)}]}, "changed outside this editor"),
            ({"peers": [{}, {"original_public_key": None}]}, "same public key"),
        ]
        for changes, message in cases:
            with self.subTest(changes=changes):
                config = await self.config()
                peers = changes.get("peers")
                if isinstance(peers, list):
                    config["peers"] = [{**config["peers"][0], **peer} for peer in peers]
                    changes = {}
                config.update(changes)
                self.calls.clear()
                with self.assertLogs("decky-wireguard"):
                    result = await self.plugin.set_connection_config(
                        HOME, config, [{"key": "ipv4.dns-priority", "value": "1"}], REVISION,
                    )
                self.assertFalse(result["success"])
                self.assertIn(message, result["error"])
                self.assertNotIn("nmcli modify", self.calls)
                self.assertNotIn("Update2", self.calls)

    async def test_advanced_properties_cannot_bypass_structured_or_startup_fields(self):
        config = await self.config()
        for key, message in [
            ("connection.autoconnect", "managed by the startup controls"),
            ("wireguard.peers", "edited in the WireGuard fields"),
            ("vpn.secrets", "Unsupported advanced property"),
            ("--help", "Invalid or duplicate"),
        ]:
            with self.subTest(key=key), self.assertLogs("decky-wireguard"):
                result = await self.plugin.set_connection_config(
                    HOME, config, [{"key": key, "value": "x"}], REVISION,
                )
                self.assertFalse(result["success"])
                self.assertIn(message, result["error"])
        self.assertNotIn("nmcli modify", self.calls)
        self.assertNotIn("offline modify", self.calls)

    async def test_create_saves_keys_and_peers_without_autoconnect_or_activation(self):
        config = await self.config()
        config["peers"][0]["original_public_key"] = None
        config["peers"][0]["preshared_key"] = ""
        created = {}
        methods = []

        async def bus(path, interface, method, signature="", *values):
            methods.append(method)
            if method == "AddConnection":
                created.update(values[0])
                return [CONNECTION_PATH]
            self.fail(f"Unexpected method: {method}")

        with patch("main._dbus_call", side_effect=bus), patch("main._nmcli") as nmcli:
            result = await self.plugin.create_connection_config(config, [])
        self.assertTrue(result["success"], result)
        self.assertEqual(methods, ["AddConnection"])
        self.assertEqual(created["connection"]["uuid"], v("s", result["uuid"]))
        self.assertEqual(created["connection"]["id"], v("s", "Home"))
        self.assertEqual(created["connection"]["type"], v("s", "wireguard"))
        self.assertEqual(created["connection"]["autoconnect"], v("b", False))
        self.assertRegex(created["connection"]["interface-name"]["data"], r"^wg-[0-9a-f]{12}$")
        self.assertEqual(created["wireguard"]["private-key"], v("s", PRIVATE))
        self.assertEqual(created["ipv4"]["method"], v("s", "manual"))
        [peer] = created["wireguard"]["peers"]["data"]
        self.assertEqual(peer["public-key"], v("s", PEER))
        self.assertEqual(peer["preshared-key-flags"], v("u", 4))
        self.assertNotIn("preshared-key", peer)
        nmcli.assert_not_called()

    async def test_timed_out_dbus_request_is_an_unconfirmed_write(self):
        reader = asyncio.StreamReader()
        writer = Mock(write=Mock(), drain=AsyncMock())
        with patch("main.DBUS_TIMEOUT", 0.01), self.assertRaises(UnconfirmedWrite):
            await _Bus(reader, writer).call("/", "org.example", "Update2")

    async def test_lost_create_reply_reconciles_the_draft_uuid_without_deleting(self):
        config = {**await self.config(), "peers": []}
        with (patch("main._dbus_call", side_effect=UnconfirmedWrite("No reply")) as add,
              patch("main._matches_persisted_profile", return_value=False) as verify,
              self.assertLogs("decky-wireguard")):
            result = await self.plugin.create_connection_config(config, [], WORK)
        self.assertIn("not confirmed", result["error"])
        self.assertEqual(verify.await_args.args[0]["connection"]["uuid"], v("s", WORK))
        add.assert_awaited_once()
        self.assertEqual(add.await_args.args[4]["connection"]["uuid"], v("s", WORK))

    async def test_lost_update_reply_confirms_only_matching_persisted_settings(self):
        intended = {"connection": {"id": v("s", "Changed"), "uuid": v("s", HOME)}}
        for actual, dirty, version, confirmed in (
            (intended, False, 43, True), (intended, True, 43, False),
            ({}, False, 43, False), (intended, False, 44, False),
        ):
            with (self.subTest(dirty=dirty, version=version, actual=actual),
                  patch("main._nm_snapshot", return_value=(43, actual)),
                  patch("main._nm_profile_ref", return_value=REF),
                  patch("main._nm_revision", return_value=version),
                  patch.object(self.bus, "call", side_effect=[UnconfirmedWrite("No reply"),
                                                             [v("b", dirty)]]) as bus):
                if confirmed:
                    await _nm_update(self.bus, REF, intended, 42)
                else:
                    with self.assertRaises(UnconfirmedWrite):
                        await _nm_update(self.bus, REF, intended, 42)
                self.assertEqual([call.args[2] for call in bus.await_args_list], ["Update2", "Get"])

    async def test_duplicate_create_only_succeeds_on_a_verified_match(self):
        config = {**await self.config(), "peers": []}
        with (patch("main._dbus_call", side_effect=DuplicateUuid("Already exists")) as add,
              patch("main._matches_persisted_profile", side_effect=[True, False])):
            first = await self.plugin.create_connection_config(config, [], WORK)
            with self.assertLogs("decky-wireguard"):
                second = await self.plugin.create_connection_config(config, [], WORK)
        self.assertEqual(first, {"success": True, "uuid": WORK})
        self.assertEqual((second["success"], second["code"], second["uuid"]), (False, "uuid_exists", WORK))
        self.assertEqual([call.args[2] for call in add.await_args_list], ["AddConnection", "AddConnection"])
        self.assertFalse(self.updates)

    async def test_invalid_new_profiles_are_rejected_before_creation(self):
        config = await self.config()
        config["peers"] = []
        for changes, advanced in [
            ({"name": ""}, []), ({"private_key": ""}, []),
            ({"addresses": "invalid"}, []),
            ({}, [{"key": "connection.uuid", "value": WORK}]),
            ({}, [{"key": "connection.type", "value": "ethernet"}]),
            ({}, [{"key": "connection.autoconnect", "value": "yes"}]),
        ]:
            with (
                self.subTest(changes=changes, advanced=advanced),
                patch("main._dbus_call") as bus,
                self.assertLogs("decky-wireguard"),
            ):
                result = await self.plugin.create_connection_config({**config, **changes}, advanced)
            self.assertFalse(result["success"])
            bus.assert_not_called()

    async def test_unchanged_required_fields_and_secrets_are_validated_before_advanced_saves(self):
        stored = copy.deepcopy(self.settings)
        secrets = copy.deepcopy(self.secrets)
        noncanonical = PRIVATE[:-2] + "B="
        for field, value, message in [
            ("name", "", "Name is required"),
            ("private-key", "", "Private key is required"),
            ("private-key", noncanonical, "Private key must be a 44-character"),
            ("public-key", "", "Peer 1 public key is required"),
            ("preshared-key", noncanonical, "Peer 1 preshared key must be a 44-character"),
        ]:
            with self.subTest(field=field, message=message):
                self.settings = copy.deepcopy(stored)
                self.secrets = copy.deepcopy(secrets)
                if field == "name":
                    self.settings["connection"]["id"] = v("s", value)
                elif field == "private-key":
                    self.secrets["wireguard"]["private-key"] = v("s", value)
                elif field == "public-key":
                    self.settings["wireguard"]["peers"]["data"][0]["public-key"] = v("s", value)
                else:
                    self.secrets["wireguard"]["peers"]["data"][0]["preshared-key"] = v("s", value)
                config = await self.config()
                self.calls.clear()
                with self.assertLogs("decky-wireguard"):
                    result = await self.plugin.set_connection_config(
                        HOME, config, [{"key": "ipv4.dns-priority", "value": "-50"}], REVISION,
                    )
                self.assertFalse(result["success"])
                self.assertIn(message, result["error"])
                self.assertNotIn(noncanonical, result["error"])
                self.assertNotIn("nmcli modify", self.calls)
                self.assertNotIn("Update2", self.calls)

    async def test_incompatible_advanced_settings_are_rejected_before_any_write(self):
        config = await self.config()
        cases = [
            ("ipv4.method", "auto", "WireGuard supports only manual, disabled"),
            ("ipv4.method", "shared", "WireGuard supports only manual, disabled"),
            ("ipv4.method", "link-local", "WireGuard supports only manual, disabled"),
            ("ipv4.method", "", "WireGuard supports only manual, disabled"),
            ("ipv4.method", "disabled", "cannot be combined with static addresses"),
            ("ipv6.method", "auto", "WireGuard supports only"),
            ("ipv6.method", "shared", "WireGuard supports only"),
            ("ipv6.method", "manual", "requires at least one IPv6 address"),
            ("connection.interface-name", "", "Interface name must be"),
            ("connection.interface-name", "wg" * 8, "Interface name must be"),
            ("connection.interface-name", "\u00e9" * 8, "Interface name must be"),
            ("connection.interface-name", "..", "Interface name must be"),
            ("connection.interface-name", " wg0", "Interface name must be"),
            ("connection.interface-name", "wg/0", "Interface name must be"),
            ("connection.interface-name", "wg:0", "Interface name must be"),
            ("wireguard.fwmark", "-1", "Firewall mark must be"),
            ("wireguard.fwmark", "4294967296", "Firewall mark must be"),
            ("wireguard.fwmark", "0x100000000", "Firewall mark must be"),
            ("wireguard.fwmark", "0x", "Firewall mark must be"),
            ("connection.type", "ethernet", "cannot be overridden"),
            ("connection.uuid", WORK, "cannot be overridden"),
            ("connection.t", "ethernet", "full property name"),
            ("con.uuid", WORK, "full property name"),
            ("ip4.method", "auto", "full property name"),
            ("wireguard.f", "0x100000000", "full property name"),
        ]
        for key, value, message in cases:
            with self.subTest(key=key, value=value):
                self.calls.clear()
                with self.assertLogs("decky-wireguard"):
                    result = await self.plugin.set_connection_config(
                        HOME, config, [{"key": key, "value": value}], REVISION,
                    )
                self.assertFalse(result["success"])
                self.assertIn(message, result["error"])
                self.assertNotIn("nmcli modify", self.calls)
                self.assertNotIn("Update2", self.calls)

    async def test_format_failures_block_both_creating_and_updating_profiles(self):
        valid = await self.config()
        valid["peers"][0]["original_public_key"] = None
        cases = [
            ({"name": "Bad\0name"}, {}, "Name is required"),
            ({"private_key": PRIVATE + "="}, {}, "Private key must be"),
            ({"addresses": "fd00::2/129"}, {}, "Address:"),
            ({"addresses": "fe80::2%wg0/64"}, {}, "Address:"),
            ({"dns": "999.1.1.1"}, {}, "DNS:"),
            ({"dns": "bad/domain"}, {}, "DNS:"),
            ({"listen_port": "65536"}, {}, "Listen port must be"),
            ({"listen_port": "9" * 16000}, {}, "Listen port must be"),
            ({"mtu": "4294967296"}, {}, "MTU must be"),
            ({}, {"public_key": PEER[:-2] + "B="}, "Peer 1 public key must be"),
            ({}, {"preshared_key": "secret-but-not-a-key"}, "Peer 1 preshared key must be"),
            ({}, {"allowed_ips": "0.0.0.0/33"}, "Peer 1 allowed IPs:"),
            ({}, {"allowed_ips": "fe80::%wg0/64"}, "Peer 1 allowed IPs:"),
            ({}, {"endpoint": "999.1.1.1:51820"}, "Peer 1 must be host:port"),
            ({}, {"endpoint": "[fd00::1]:65536"}, "Peer 1 must be host:port"),
            ({}, {"endpoint": "vpn.example.com:0"}, "Peer 1 must be host:port"),
            ({}, {"endpoint": "vpn.example.com:" + "9" * 15000}, "Peer 1 must be host:port"),
            ({}, {"persistent_keepalive": "65536"}, "persistent keepalive must be"),
            ({}, {"persistent_keepalive": "1.5"}, "persistent keepalive must be"),
            ({}, {"persistent_keepalive": "\u0662\u0665"}, "persistent keepalive must be"),
        ]
        for index, (changes, peer_changes, message) in enumerate(cases):
            for uuid in (None, HOME):
                with self.subTest(case=index, creating=uuid is None):
                    config = {**valid, **changes, "peers": [{**valid["peers"][0], **peer_changes}]}
                    self.calls.clear()
                    with self.assertLogs("decky-wireguard"):
                        result = await self.plugin.set_connection_config(uuid, config, [], REVISION if uuid else None)
                    self.assertFalse(result["success"])
                    self.assertIn(message, result["error"])
                    self.assertNotIn("secret-but-not-a-key", result["error"])
                    self.assertNotIn("AddConnection", self.calls)
                    self.assertNotIn("nmcli modify", self.calls)
                    self.assertNotIn("Update2", self.calls)

    async def test_valid_boundaries_and_server_style_optional_omissions_are_accepted(self):
        valid = await self.config()
        for port, keepalive, mtu in [("0", "off", "0"), ("65535", "65535", "4294967295")]:
            with self.subTest(port=port, keepalive=keepalive, mtu=mtu):
                config = {
                    **valid, "listen_port": port, "mtu": mtu,
                    "peers": [{
                        **valid["peers"][0], "allowed_ips": "", "endpoint": "",
                        "preshared_key": "", "persistent_keepalive": keepalive,
                    }],
                }
                result = await self.plugin.set_connection_config(HOME, config, [], REVISION)
                self.assertTrue(result["success"], result)
                update = self.updates[-1]
                self.assertEqual(update["wireguard"]["listen-port"], v("u", int(port)))
                self.assertEqual(update["wireguard"]["mtu"], v("u", int(mtu)))
                peer = update["wireguard"]["peers"]["data"][0]
                self.assertEqual(peer["persistent-keepalive"], v("u", 0 if keepalive == "off" else 65535))
                self.assertEqual(peer["allowed-ips"], v("as", []))
                self.assertNotIn("endpoint", peer)
        result = await self.plugin.set_connection_config(
            HOME, {**valid, "addresses": "", "dns": "", "peers": []}, [], REVISION,
        )
        self.assertTrue(result["success"], result)

    async def test_supported_advanced_values_and_firewall_mark_formats_are_accepted(self):
        config = await self.config()
        for key, value, normalized in [
            ("connection.interface-name", "a" * 15, "a" * 15),
            ("connection.interface-name", "\u00e9" * 7 + "a", "\u00e9" * 7 + "a"),
            ("ipv4.method", "manual", "manual"),
            ("ipv6.method", "disabled", "disabled"),
            ("ipv6.method", "ignore", "ignore"),
            ("ipv6.method", "link-local", "link-local"),
            ("wireguard.fwmark", "off", "0"),
            ("wireguard.fwmark", "0xffffffff", "4294967295"),
            ("wireguard.fwmark", "000051820", "51820"),
        ]:
            with (
                self.subTest(key=key, value=value),
                patch.object(self.plugin, "_profile", return_value={"uuid": HOME}),
            ):
                result = await self.plugin.set_connection_config(
                    HOME, config, [{"key": key, "value": value}], REVISION,
                )
                self.assertTrue(result["success"], result)
                group, field = key.split(".")
                value = self.updates[-1][group].get(field, {"data": 0})["data"]
                self.assertEqual(str(value), normalized)

    async def test_existing_dns_over_tls_settings_remain_editable(self):
        self.settings["ipv4"]["dns-data"] = v("as", ["10.0.0.1#dns.example"])
        config = await self.config()
        config["name"] = "Renamed"
        result = await self.plugin.set_connection_config(HOME, config, [], REVISION)
        self.assertTrue(result["success"], result)
        self.assertEqual(self.updates[-1]["ipv4"]["dns-data"], v("as", ["10.0.0.1#dns.example"]))
        self.assertNotIn("dns", self.updates[-1]["ipv4"])

    async def test_root_dns_routing_and_ip_prefix_boundaries_are_accepted(self):
        config = await self.config()
        config.update({
            "addresses": "10.0.0.2/0, fd00::2/0, fd00::3/128",
            "dns": "10.0.0.1, ~., ~example.com, .",
        })
        result = await self.plugin.set_connection_config(HOME, config, [], REVISION)
        self.assertTrue(result["success"], result)
        self.assertEqual(self.updates[-1]["ipv4"]["dns-search"], v("as", [
            "~.", "~example.com", ".",
        ]))
        self.assertEqual(
            self.updates[-1]["ipv4"]["address-data"]["data"][0]["prefix"], v("u", 0),
        )
        self.assertEqual(
            self.updates[-1]["ipv6"]["address-data"]["data"][-1]["prefix"], v("u", 128),
        )

    async def test_name_and_private_key_are_enough_to_create_a_profile(self):
        config = {
            "name": "Private VPN \u0394", "private_key": PRIVATE, "addresses": "",
            "dns": "", "listen_port": "", "mtu": "", "peers": [],
        }
        with patch("main._dbus_call", side_effect=[[CONNECTION_PATH], []]) as bus:
            result = await self.plugin.create_connection_config(config, [])
        self.assertTrue(result["success"], result)
        added = bus.await_args_list[0].args
        self.assertEqual(added[2], "AddConnection")
        settings = added[4]
        self.assertEqual(settings["connection"]["id"], v("s", config["name"]))
        self.assertEqual(settings["wireguard"]["private-key"], v("s", PRIVATE))
        self.assertEqual(settings["ipv4"]["method"], v("s", "disabled"))
        self.assertEqual(settings["ipv6"]["method"], v("s", "disabled"))
        bus.assert_awaited_once()

class ConfFileTests(unittest.IsolatedAsyncioTestCase):
    @unittest.skipIf(os.geteuid() == 0, "This fixture is owned by the user running the suite")
    async def test_read_only_import_returns_utf8_contents_without_networkmanager_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vpn.conf"
            path.write_text("\ufeff[Interface]\nPrivateKey = test\n", encoding="utf-8")
            with patch("main._nmcli") as nmcli:
                result = await Plugin().read_conf_file(str(path))
            self.assertEqual(result, {"success": True, "text": "[Interface]\nPrivateKey = test\n"})
            nmcli.assert_not_called()

    async def test_root_import_requires_a_non_root_desktop_identity_and_drops_all_credentials(self):
        account = Mock(pw_name="desktop", pw_uid=1001, pw_gid=1002)
        proc = Mock(returncode=0, communicate=AsyncMock(return_value=(b"fixture", b"")))
        with (patch("main.os.geteuid", return_value=0),
              patch.dict(os.environ, {"DECKY_USER": ""}),
              patch("main.pwd.getpwnam", return_value=account),
              patch("main.os.getgrouplist", return_value=[1002, 1003]),
              patch("main.asyncio.create_subprocess_exec", return_value=proc) as spawn):
            with self.assertLogs("decky-wireguard"):
                self.assertFalse((await Plugin().read_conf_file("/example.conf"))["success"])
            with patch.dict(os.environ, {"DECKY_USER": "root"}), patch.object(account, "pw_uid", 0), self.assertLogs("decky-wireguard"):
                self.assertFalse((await Plugin().read_conf_file("/example.conf"))["success"])
            spawn.assert_not_awaited()
            with patch.dict(os.environ, {"DECKY_USER": "desktop"}):
                self.assertEqual(await Plugin().read_conf_file("/example.conf"), {"success": True, "text": "fixture"})
            kwargs = spawn.await_args.kwargs
            self.assertEqual((kwargs["user"], kwargs["group"], kwargs["extra_groups"]), (1001, 1002, [1002, 1003]))
            self.assertEqual(spawn.await_args.args[:3], ("/usr/bin/python3", "-I", "-S"))

    async def test_import_rejects_missing_nonregular_oversized_and_non_utf8_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "large.conf").write_bytes(b"x" * (1024 * 1024 + 1))
            (root / "binary.conf").write_bytes(b"\xffPrivateKey")
            (root / "folder.conf").mkdir()
            os.mkfifo(root / "pipe.conf")
            for path in [
                root / "missing.conf", root / "large.conf", root / "binary.conf",
                root / "folder.conf", root / "pipe.conf", root / "wrong.txt",
                "relative.conf", None,
            ]:
                with self.subTest(path=path), self.assertLogs("decky-wireguard") as logs:
                    result = await Plugin().read_conf_file(str(path) if path is not None else None)
                self.assertFalse(result["success"])
                self.assertNotIn("PrivateKey", result["error"])
                self.assertNotIn("PrivateKey", "\n".join(logs.output))


class ProbeTests(unittest.IsolatedAsyncioTestCase):
    async def targets(self, allowed, device):
        with patch("main._command", new_callable=AsyncMock, return_value=allowed) as command, patch(
            "main._nmcli", new_callable=AsyncMock, return_value=device,
        ):
            result = await _probe_targets("wg0")
        command.assert_awaited_once_with("wg", "show", "wg0", "allowed-ips")
        return result

    async def test_provider_dns_and_default_route_need_no_fixed_public_service(self):
        self.assertEqual(await self.targets(
            "peer\t0.0.0.0/0 ::/0\n",
            "IP4.ADDRESS[1]:10.2.0.2/32\nIP4.DNS[1]:10.2.0.1\n",
        ), [
            ProbeTarget(ip_address("10.2.0.1"), dns=True),
            ProbeTarget(ip_address("192.0.2.1")),
        ])

    async def test_private_tunnel_without_dns_avoids_local_address(self):
        self.assertEqual(await self.targets(
            "peer\t10.50.0.0/24\n", "IP4.ADDRESS[1]:10.50.0.1/24\n",
        ), [ProbeTarget(ip_address("10.50.0.2"))])

    async def test_ipv6_only_default_route_and_escaped_dns_address(self):
        self.assertEqual(await self.targets(
            "peer\t::/0\n",
            "IP6.ADDRESS[1]:fd00\\:\\:2/128\nIP6.DNS[1]:fd00\\:\\:1\n",
        ), [
            ProbeTarget(ip_address("fd00::1"), dns=True),
            ProbeTarget(ip_address("2001:db8::1")),
        ])

    async def test_ipv6_device_output_with_unescaped_colons(self):
        self.assertEqual(await self.targets(
            "peer\tfd00::/64\n",
            "IP6.ADDRESS[1]:fd00::1/64\nIP6.DNS[1]:fd00::2\n",
        ), [
            ProbeTarget(ip_address("fd00::2"), dns=True),
            ProbeTarget(ip_address("fd00::2")),
        ])

    async def test_dns_outside_allowed_ips_is_never_probed(self):
        self.assertEqual(await self.targets(
            "peer\t10.0.0.9/32\n", "IP4.ADDRESS[1]:10.0.0.2/32\nIP4.DNS[1]:192.0.2.53\n",
        ), [ProbeTarget(ip_address("10.0.0.9"))])

    async def test_multiple_peers_use_longest_prefix_ownership(self):
        self.assertEqual(await self.targets(
            "broad\t10.0.0.0/24\nspecific\t10.0.0.1/32\n",
            "IP4.ADDRESS[1]:10.0.0.3/24\nIP4.DNS[1]:10.0.0.1\n",
        ), [
            ProbeTarget(ip_address("10.0.0.2")),
            ProbeTarget(ip_address("10.0.0.1"), dns=True),
            ProbeTarget(ip_address("10.0.0.1")),
        ])

    async def test_bad_or_unusable_addresses_are_explicit_errors(self):
        for allowed, device in [
            ("peer\t(none)\n", ""),
            ("peer\t10.0.0.2/32\n", "IP4.ADDRESS[1]:10.0.0.2/32\n"),
            ("peer\t127.0.0.0/8 224.0.0.0/4 169.254.0.0/16\n", ""),
            ("peer\tbad-network\n", ""),
            ("peer\t10.0.0.0/24\n", "unexpected:field:shape\n"),
            ("peer\t::/0\n", "IP6.DNS[1]:fd00::not-an-address\n"),
            ("peer\t::/0\n", "IP6.ADDRESS[1]\n"),
        ]:
            with self.subTest(allowed=allowed, device=device), self.assertRaises(NetworkManagerError):
                await self.targets(allowed, device)

    async def test_probes_bind_to_tunnel_and_use_dns_or_icmp_for_both_ip_families(self):
        targets = [
            ProbeTarget(ip_address("10.0.0.53"), dns=True),
            ProbeTarget(ip_address("10.0.0.1")),
            ProbeTarget(ip_address("fd00::53"), dns=True),
            ProbeTarget(ip_address("fd00::1")),
        ]
        send = AsyncMock()
        with patch("main.socket.socket") as create, patch.object(
            asyncio.get_running_loop(), "sock_sendto", send,
        ):
            await _send_probe("wg0", targets)
        protocols = [call.args[2] for call in create.call_args_list]
        self.assertEqual(protocols, [
            socket.IPPROTO_UDP, socket.IPPROTO_ICMP, socket.IPPROTO_UDP, socket.IPPROTO_ICMPV6,
        ])
        probe = create.return_value.__enter__.return_value
        probe.setsockopt.assert_called_with(
            socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"wg0\0",
        )
        self.assertEqual(probe.setsockopt.call_count, 4)
        probe.setblocking.assert_called_with(False)
        packets = [call.args[1] for call in send.await_args_list]
        self.assertEqual(packets[0][2:], b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\0\0\2\0\1")
        self.assertEqual(packets[1][0], 8)
        self.assertEqual(packets[3][0], 128)
        self.assertEqual(send.await_args_list[0].args[2], ("10.0.0.53", 53))
        self.assertEqual(send.await_args_list[3].args[2], ("fd00::1", 0, 0, 0))

    async def test_binding_failure_never_sends_unbound_probe(self):
        with patch("main.socket.socket") as create, patch.object(
            asyncio.get_running_loop(), "sock_sendto", new_callable=AsyncMock,
        ) as send:
            create.return_value.__enter__.return_value.setsockopt.side_effect = PermissionError(
                "denied",
            )
            with self.assertLogs("decky-wireguard"), self.assertRaisesRegex(
                NetworkManagerError, "denied",
            ):
                await _send_probe("wg0", [ProbeTarget(ip_address("10.0.0.1"))])
            send.assert_not_awaited()

    async def test_failed_probe_does_not_prevent_other_targets_from_being_tried(self):
        with patch("main.socket.socket"), patch.object(
            asyncio.get_running_loop(), "sock_sendto",
            new_callable=AsyncMock, side_effect=[OSError("no route"), None],
        ) as send, self.assertLogs("decky-wireguard"):
            await _send_probe("wg0", [
                ProbeTarget(ip_address("10.0.0.1")), ProbeTarget(ip_address("fd00::1")),
            ])
        self.assertEqual(send.await_count, 2)

    async def test_restricted_ping_sockets_use_root_raw_socket_with_valid_checksum(self):
        raw = Mock()
        with patch(
            "main.socket.socket", side_effect=[PermissionError("ping group restricted"), raw],
        ) as create, patch.object(
            asyncio.get_running_loop(), "sock_sendto", new_callable=AsyncMock,
        ) as send:
            raw.__enter__ = Mock(return_value=raw)
            raw.__exit__ = Mock(return_value=False)
            await _send_probe("wg0", [ProbeTarget(ip_address("10.0.0.1"))])
        self.assertEqual(
            create.call_args.args, (socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP),
        )
        self.assertEqual(send.await_args.args[1], b"\x08\0\xf7\xfe\0\0\0\1")
        raw.setsockopt.assert_called_once_with(
            socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"wg0\0",
        )


class SubprocessTests(unittest.IsolatedAsyncioTestCase):
    async def test_untrusted_bus_peer_is_rejected_before_any_bytes_are_sent(self):
        writer = bus_writer(2000)
        with (patch("main.asyncio.open_unix_connection", return_value=(AsyncMock(), writer)),
              patch("main.pwd.getpwnam", return_value=Mock(pw_uid=81)),
              self.assertRaisesRegex(NetworkManagerError, "trusted bus service")):
            await _dbus_call(NM_SETTINGS_PATH, "org.freedesktop.NetworkManager.Settings", "AddConnection")
        writer.write.assert_not_called()
        writer.transport.abort.assert_called_once()
        with patch("main.pwd.getpwnam", return_value=Mock(pw_uid=81)):
            _verify_bus_peer(bus_writer(81))

    def test_system_bus_address_never_falls_back_to_another_socket(self):
        for address, expected in [
            ("unix:path=/tmp/test%20bus", (b"/tmp/test bus", None)),
            ("unix:abstract=test,guid=" + "a" * 32, (b"\0test", "a" * 32)),
        ]:
            with self.subTest(address=address), patch.dict(os.environ, {"DBUS_SYSTEM_BUS_ADDRESS": address}):
                self.assertEqual(_system_bus_address(), expected)
        for address in ("tcp:host=test", "unix:path=/one;unix:path=/two", "unix:path=relative",
                        "unix:path=/a,path=/b", "unix:path=/tmp/%00", "unix:path=/bad%zz"):
            with (self.subTest(address=address), patch.dict(os.environ, {"DBUS_SYSTEM_BUS_ADDRESS": address}),
                  self.assertRaises(NetworkManagerError)):
                _system_bus_address()

    async def test_dbus_error_reports_message_without_echoing_secrets(self):
        secret = "sensitive-private-key-value"
        reader = asyncio.StreamReader()
        reader.feed_data(
            b"OK test-guid\r\n"
            + _dbus_message(2, 42, signature="s", values=[":1.1"], reply_serial=1)
            + _dbus_message(
                3, 43, signature="s",
                values=[f"Invalid wireguard.private-key: {secret}"],
                reply_serial=2, error_name="org.freedesktop.NetworkManager.Error.InvalidProperty",
            )
        )
        reader.feed_eof()
        writer = bus_writer()
        with patch(
            "main.asyncio.open_unix_connection", new_callable=AsyncMock,
            return_value=(reader, writer),
        ):
            with self.assertRaises(NetworkManagerError) as caught:
                await _dbus_call(
                    CONNECTION_PATH, "org.freedesktop.NetworkManager.Settings.Connection",
                    "Update", "a{sa{sv}}",
                    {"wireguard": {"private-key": v("s", secret)}},
                )
        self.assertIn("Invalid wireguard.private-key", str(caught.exception))
        self.assertIn("org.freedesktop.NetworkManager.Error.InvalidProperty", str(caught.exception))
        self.assertNotIn(secret, str(caught.exception))

    async def test_dbus_call_cancellation_closes_its_socket(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"OK test-guid\r\n")
        hello_sent = asyncio.Event()
        writer = bus_writer()
        writes = []
        drains = 0

        def write(data):
            writes.append(data)

        async def drain():
            nonlocal drains
            drains += 1
            if drains == 2:
                hello_sent.set()

        writer.write = write
        writer.drain = drain
        writer.wait_closed = AsyncMock()
        with patch(
            "main.asyncio.open_unix_connection", new_callable=AsyncMock,
            return_value=(reader, writer),
        ):
            request = asyncio.create_task(_dbus_call(
                CONNECTION_PATH, "org.freedesktop.NetworkManager.Settings.Connection",
                "Update", "a{sa{sv}}", {},
            ))
            await hello_sent.wait()
            request.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await request
        self.assertEqual(len(writes), 3)
        writer.transport.abort.assert_called_once_with()
        writer.wait_closed.assert_awaited_once()

    async def test_transfer_query_only_reads_counters_and_does_not_use_sent_bytes(self):
        with patch(
            "main._command", new_callable=AsyncMock, return_value="peer\t123\t999999\n",
        ) as command:
            self.assertEqual(await _received_bytes("wg0"), {"peer": 123})
        command.assert_awaited_once_with("wg", "show", "wg0", "transfer")
        with patch(
            "main._command", new_callable=AsyncMock, return_value="peer\t123\t999999\n",
        ):
            self.assertEqual(await _transfer_counters("wg0"), {"peer": (123, 999999)})
        for output in ["peer\t-1\t0\n", "peer\t1\n", "peer\tx\t10\n", "peer\t1\tbad\n"]:
            with (
                self.subTest(output=output),
                patch("main._command", new_callable=AsyncMock, return_value=output),
                self.assertRaisesRegex(NetworkManagerError, "unexpected transfer data"),
            ):
                await _transfer_counters("wg0")

    async def test_handshake_query_only_requests_timestamps_without_secrets(self):
        process = Mock(
            returncode=0, communicate=AsyncMock(return_value=(b"peer1\t0\npeer2\t1234\n", b"")),
        )
        with patch("main.asyncio.create_subprocess_exec", return_value=process) as spawn:
            self.assertEqual(await _handshakes("wg0"), {"peer1": 0, "peer2": 1234})
        self.assertEqual(spawn.call_args.args, ("wg", "show", "wg0", "latest-handshakes"))
        self.assertEqual(spawn.call_args.kwargs["stdin"], asyncio.subprocess.DEVNULL)

    async def test_handshake_query_rejects_malformed_timestamps(self):
        for output in ["peer\t-1\n", "peer\tinvalid\n", "peer\n", "peer\t1\textra\n"]:
            with (
                self.subTest(output=output),
                patch("main._command", new_callable=AsyncMock, return_value=output),
                self.assertRaisesRegex(NetworkManagerError, "unexpected handshake data"),
            ):
                await _handshakes("wg0")

    async def test_missing_handshake_tool_has_actionable_error(self):
        with (
            patch("main.asyncio.create_subprocess_exec", side_effect=FileNotFoundError()),
            self.assertRaisesRegex(NetworkManagerError, "Install wireguard-tools"),
        ):
            await _handshakes("wg0")

    async def test_nmcli_uses_argument_vector_locale_and_no_interactive_input(self):
        process = Mock(returncode=0, communicate=AsyncMock(return_value=(b"result\n", b"")))
        with patch("main.asyncio.create_subprocess_exec", new_callable=AsyncMock) as spawn:
            spawn.return_value = process
            self.assertEqual(await _nmcli(*FIELDS), "result\n")
        args, kwargs = spawn.call_args
        self.assertEqual(
            args, ("nmcli", "--terse", "--escape", "yes", "--colors", "no", "--wait", "10", *FIELDS)
        )
        self.assertEqual(kwargs["env"]["LC_ALL"], "C")
        self.assertEqual(kwargs["stdin"], asyncio.subprocess.DEVNULL)

    async def test_missing_or_unexecutable_nmcli_has_actionable_error(self):
        for error, message in [
            (FileNotFoundError(), "nmcli is not installed"),
            (PermissionError("denied"), "Unable to start nmcli"),
        ]:
            with (
                self.subTest(error=error),
                patch("main.asyncio.create_subprocess_exec", side_effect=error),
                self.assertRaisesRegex(NetworkManagerError, message),
            ):
                await _nmcli(*FIELDS)

    async def test_command_error_includes_nmcli_diagnostics(self):
        process = Mock(
            returncode=4,
            communicate=AsyncMock(return_value=(b"", b"Error: activation failed")),
        )
        with (
            patch("main.asyncio.create_subprocess_exec", return_value=process),
            self.assertRaisesRegex(NetworkManagerError, r"nmcli failed \(4\): Error: activation failed"),
        ):
            await _nmcli("connection", "up", "uuid", HOME)

    async def test_timeout_and_cancellation_kill_and_reap_process(self):
        for failure in [TimeoutError(), asyncio.CancelledError()]:
            with self.subTest(failure=type(failure).__name__):
                process = Mock(
                    returncode=None,
                    communicate=AsyncMock(side_effect=[failure, (b"", b"")]),
                )
                expected = (
                    asyncio.CancelledError if isinstance(failure, asyncio.CancelledError)
                    else NetworkManagerError
                )
                with patch("main.asyncio.create_subprocess_exec", return_value=process), self.assertRaises(expected):
                    await _nmcli(*FIELDS)
                process.kill.assert_called_once_with()
                self.assertEqual(process.communicate.await_count, 2)


if __name__ == "__main__":
    unittest.main()
