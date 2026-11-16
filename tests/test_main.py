import asyncio
import json
import os
import socket
import tempfile
import unittest
from ipaddress import ip_address
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from main import (
    NetworkManagerError,
    Plugin,
    ProbeTarget,
    _handshakes,
    _nmcli,
    _probe_targets,
    _received_bytes,
    _send_probe,
)


HOME = "11111111-1111-4111-8111-111111111111"
WORK = "22222222-2222-4222-8222-222222222222"
WIFI = "33333333-3333-4333-8333-333333333333"
FIELDS = ("--fields", "UUID,TYPE,NAME,DEVICE,STATE,ACTIVE-PATH", "connection", "show")


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
            with self.subTest(responses=responses), patch(
                "main._command", new_callable=AsyncMock, return_value="b true\nb true\n",
            ), patch("main._nmcli", new_callable=AsyncMock, side_effect=responses):
                with self.assertRaisesRegex(NetworkManagerError, "unexpected"):
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
        self.assertEqual(await self.plugin.get_profiles(), {
            "success": True,
            "profiles": [
                {
                    "uuid": HOME, "name": "home", "device": "", "state": "disconnected",
                    "handshake": "inactive", "handshake_error": None,
                },
                {
                    "uuid": WORK, "name": "Work: VPN\\Office", "device": "wg0", "state": "connected",
                    "handshake": "waiting", "handshake_error": None,
                },
            ],
        })
        self.nmcli.assert_awaited_once_with(*FIELDS)

    async def test_empty_list_is_success(self):
        self.nmcli.return_value = ""
        self.assertEqual(await self.plugin.get_profiles(), {"success": True, "profiles": []})

    async def test_connection_settings_include_secrets_and_profile_properties(self):
        self.nmcli.side_effect = [
            f"{HOME}:wireguard:Home:::\n",
            "GENERAL.NAME:Home\n"
            "connection.id:Home\\: VPN\n"
            "connection.autoconnect:yes\n"
            "wireguard.private-key:private-key\n"
            "wireguard.peers:public-key=peer;endpoint=host\\:51820;allowed-ips=0.0.0.0/0\n",
        ]
        result = await self.plugin.get_connection_settings(HOME)
        self.assertEqual(result, {
            "success": True,
            "settings": [
                {"key": "connection.id", "value": "Home: VPN"},
                {"key": "wireguard.private-key", "value": "private-key"},
                {
                    "key": "wireguard.peers",
                    "value": "public-key=peer;endpoint=host:51820;allowed-ips=0.0.0.0/0",
                },
            ],
        })
        self.nmcli.assert_awaited_with(
            "--show-secrets", "--fields", "all", "connection", "show", "uuid", HOME,
        )

    async def test_connection_settings_update_uses_uuid_and_rejects_invalid_fields(self):
        self.nmcli.side_effect = [f"{HOME}:wireguard:Home:::\n", ""]
        self.assertEqual(await self.plugin.set_connection_settings(HOME, [
            {"key": "wireguard.private-key", "value": "replacement"},
            {"key": "wireguard.peers", "value": "allowed-ips=10.0.0.0/8"},
        ]), {"success": True})
        self.nmcli.assert_awaited_with(
            "connection", "modify", "uuid", HOME,
            "wireguard.private-key", "replacement",
            "wireguard.peers", "allowed-ips=10.0.0.0/8",
        )
        self.nmcli.reset_mock()
        with self.assertLogs("decky-wireguard"):
            result = await self.plugin.set_connection_settings(HOME, [
                {"key": "connection.autoconnect", "value": "yes"},
            ])
        self.assertFalse(result["success"])
        self.assertIn("managed by the startup controls", result["error"])
        self.nmcli.assert_not_awaited()
        with self.assertLogs("decky-wireguard"):
            result = await self.plugin.set_connection_settings(HOME, [
                {"key": "--help", "value": "ignored"},
            ])
        self.assertFalse(result["success"])
        self.nmcli.assert_not_awaited()

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
                    f"{HOME}:wireguard:Same name:wg0:{initial}:/active/1\n"
                    f"{WORK}:wireguard:Same name:wg1:activated:/active/2\n",
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
        self.probe.assert_awaited_once()

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
            clock.return_value = 109.999
            self.assertEqual(await self.handshake_status(), "waiting")
            self.assertEqual(self.probe.await_count, 1)
            clock.return_value = 110
            self.assertEqual(await self.handshake_status(), "waiting")
            self.assertEqual(self.probe.await_count, 2)
            clock.return_value = 130
            self.assertEqual(await self.handshake_status(), "timeout")
            self.targets.assert_awaited_once_with("wg0")
            self.received.return_value = {"peer": 0}
            # First observations are baselines, not newly received traffic.
            self.assertEqual(await self.handshake_status(), "timeout")

    async def test_receive_baseline_resets_for_reactivation(self):
        self.nmcli.return_value = f"{HOME}:wireguard:Home:wg0:activated:/active/1\n"
        self.received.return_value = {"peer": 1000}
        await self.handshake_status()
        self.received.return_value = {"peer": 1032}
        self.assertEqual(await self.handshake_status(), "established")
        self.nmcli.return_value = f"{HOME}:wireguard:Home:wg0:activated:/active/2\n"
        self.assertEqual(await self.handshake_status(), "waiting")
        self.assertEqual(self.probe.await_count, 2)
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
        self.assertEqual(await self.handshake_status(), "established")


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
        ]:
            with self.subTest(allowed=allowed, device=device):
                with self.assertRaises(NetworkManagerError):
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
    async def test_transfer_query_only_reads_counters_and_does_not_use_sent_bytes(self):
        with patch(
            "main._command", new_callable=AsyncMock, return_value="peer\t123\t999999\n",
        ) as command:
            self.assertEqual(await _received_bytes("wg0"), {"peer": 123})
        command.assert_awaited_once_with("wg", "show", "wg0", "transfer")
        for output in ["peer\t-1\t0\n", "peer\t1\n", "peer\tx\t10\n", "peer\t1\tbad\n"]:
            with self.subTest(output=output), patch(
                "main._command", new_callable=AsyncMock, return_value=output,
            ):
                with self.assertRaisesRegex(NetworkManagerError, "unexpected transfer data"):
                    await _received_bytes("wg0")

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
            with self.subTest(output=output), patch(
                "main._command", new_callable=AsyncMock, return_value=output,
            ):
                with self.assertRaisesRegex(NetworkManagerError, "unexpected handshake data"):
                    await _handshakes("wg0")

    async def test_missing_handshake_tool_has_actionable_error(self):
        with patch("main.asyncio.create_subprocess_exec", side_effect=FileNotFoundError()):
            with self.assertRaisesRegex(NetworkManagerError, "Install wireguard-tools"):
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
            with self.subTest(error=error):
                with patch("main.asyncio.create_subprocess_exec", side_effect=error):
                    with self.assertRaisesRegex(NetworkManagerError, message):
                        await _nmcli(*FIELDS)

    async def test_command_error_includes_nmcli_diagnostics(self):
        process = Mock(
            returncode=4,
            communicate=AsyncMock(return_value=(b"", b"Error: activation failed")),
        )
        with patch("main.asyncio.create_subprocess_exec", return_value=process):
            with self.assertRaisesRegex(NetworkManagerError, r"nmcli failed \(4\): Error: activation failed"):
                await _nmcli("connection", "up", "uuid", HOME)

    async def test_timeout_and_cancellation_kill_and_reap_process(self):
        for failure in [asyncio.TimeoutError(), asyncio.CancelledError()]:
            with self.subTest(failure=type(failure).__name__):
                process = Mock(
                    returncode=None,
                    communicate=AsyncMock(side_effect=[failure, (b"", b"")]),
                )
                expected = (
                    asyncio.CancelledError if isinstance(failure, asyncio.CancelledError)
                    else NetworkManagerError
                )
                with patch("main.asyncio.create_subprocess_exec", return_value=process):
                    with self.assertRaises(expected):
                        await _nmcli(*FIELDS)
                process.kill.assert_called_once_with()
                self.assertEqual(process.communicate.await_count, 2)


if __name__ == "__main__":
    unittest.main()
