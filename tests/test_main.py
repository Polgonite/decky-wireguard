import asyncio
import unittest
from unittest.mock import AsyncMock, Mock, patch

from main import NetworkManagerError, Plugin, _handshakes, _nmcli


HOME = "11111111-1111-4111-8111-111111111111"
WORK = "22222222-2222-4222-8222-222222222222"
WIFI = "33333333-3333-4333-8333-333333333333"
FIELDS = ("--fields", "UUID,TYPE,NAME,DEVICE,STATE,ACTIVE-PATH", "connection", "show")


class ProfileTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.plugin = Plugin()
        self.patcher = patch("main._nmcli", new_callable=AsyncMock)
        self.nmcli = self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.handshake_patcher = patch("main._handshakes", new_callable=AsyncMock, return_value={})
        self.handshakes = self.handshake_patcher.start()
        self.addCleanup(self.handshake_patcher.stop)

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


class SubprocessTests(unittest.IsolatedAsyncioTestCase):
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
