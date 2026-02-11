import time
import unittest
from typing import Any
from unittest.mock import MagicMock, patch

from wg_monitor import MonitorStats, PeerInfo, WireGuardMonitor


def _make_monitor(
    interface: str | None = None,
    on_change_script: str | None = None,
) -> WireGuardMonitor:
    with patch.object(WireGuardMonitor, "_setup_logging"), patch.object(
        WireGuardMonitor, "_validate_config"
    ), patch.object(
        WireGuardMonitor, "_validate_log_path", return_value="/dev/null"
    ), patch.object(
        WireGuardMonitor, "_resolve_wg_path", return_value="/usr/bin/wg"
    ):
        monitor = WireGuardMonitor(
            log_path="/dev/null",
            interval=30,
            threshold=180,
            stats_interval=3600,
            debug=True,
            interface=interface,
            on_change_script=on_change_script,
        )
    monitor.logger = MagicMock()
    return monitor


class TestMonitor(unittest.TestCase):
    def setUp(self) -> None:
        self.monitor = _make_monitor()

    @patch("wg_monitor.subprocess.run")
    def test_fetch_dump_success(self, mock_run: Any) -> None:
        mock_result = MagicMock()
        mock_result.stdout = "mock output"
        mock_run.return_value = mock_result

        output = self.monitor._fetch_dump()
        self.assertEqual(output, "mock output")

        call_args = mock_run.call_args
        self.assertEqual(call_args[0][0], ["/usr/bin/wg", "show", "all", "dump"])

    @patch("wg_monitor.subprocess.run")
    def test_fetch_dump_failure(self, mock_run: Any) -> None:
        from subprocess import CalledProcessError

        mock_run.side_effect = CalledProcessError(1, ["wg"], stderr="error")

        output = self.monitor._fetch_dump()
        self.assertEqual(output, "")
        self.monitor.logger.error.assert_called()  # type: ignore

    def test_state_change_detection(self) -> None:
        pubkey = "A" * 43 + "="
        iface = "wg0"
        peer_key = (iface, pubkey)

        peer = PeerInfo(
            iface, pubkey, "1.1.1.1:123", "10.0.0.1/32", 1678888888, True
        )

        self.assertNotIn(peer_key, self.monitor.peer_states)

        if peer_key not in self.monitor.peer_states:
            self.monitor.peer_states[peer_key] = peer

        self.assertIn(peer_key, self.monitor.peer_states)
        self.assertEqual(self.monitor.peer_states[peer_key], peer)
        self.assertTrue(self.monitor.peer_states[peer_key].is_online)

        peer_offline = PeerInfo(
            iface, pubkey, "1.1.1.1:123", "10.0.0.1/32", 1678888888, False
        )

        last_peer = self.monitor.peer_states[peer_key]
        self.assertTrue(last_peer.is_online)
        self.assertFalse(peer_offline.is_online)

        self.monitor.peer_states[peer_key] = peer_offline

        self.assertEqual(self.monitor.peer_states[peer_key], peer_offline)

    def test_stats_is_monitor_stats(self) -> None:
        self.assertIsInstance(self.monitor.stats, MonitorStats)
        self.assertEqual(self.monitor.stats.total_checks, 0)
        self.assertEqual(self.monitor.stats.failed_checks, 0)
        self.assertEqual(self.monitor.stats.state_changes, 0)
        self.assertEqual(self.monitor.stats.parse_errors, 0)

    def test_stop_event_exists(self) -> None:
        self.assertFalse(self.monitor._stop_event.is_set())
        self.monitor._stop_event.set()
        self.assertTrue(self.monitor._stop_event.is_set())

    def test_constructor_with_interface_and_script(self) -> None:
        monitor = _make_monitor(interface="wg0", on_change_script="/bin/true")
        self.assertEqual(monitor.interface, "wg0")
        self.assertEqual(monitor.on_change_script, "/bin/true")

    def test_constructor_defaults(self) -> None:
        monitor = _make_monitor()
        self.assertIsNone(monitor.interface)
        self.assertIsNone(monitor.on_change_script)


class TestIsInterfaceLine(unittest.TestCase):
    def test_interface_line_with_port(self) -> None:
        parts = ["wg0", "PRIVATE_KEY", "PUBLIC_KEY", "51820", "off"]
        self.assertTrue(WireGuardMonitor._is_interface_line(parts))

    def test_interface_line_with_off(self) -> None:
        parts = ["wg0", "PRIVATE_KEY", "PUBLIC_KEY", "off", "off"]
        self.assertTrue(WireGuardMonitor._is_interface_line(parts))

    def test_peer_line(self) -> None:
        pubkey = "A" * 43 + "="
        parts = [
            "wg0", pubkey, "(none)", "1.1.1.1:123",
            "10.0.0.1/32", "1678888888", "0", "0", "0",
        ]
        self.assertFalse(WireGuardMonitor._is_interface_line(parts))

    def test_too_few_parts(self) -> None:
        self.assertFalse(WireGuardMonitor._is_interface_line(["wg0", "a", "b"]))

    def test_non_digit_listen_port(self) -> None:
        parts = ["wg0", "KEY", "KEY", "not_a_port", "off"]
        self.assertFalse(WireGuardMonitor._is_interface_line(parts))


class TestRunOnChangeScript(unittest.TestCase):
    def setUp(self) -> None:
        self.peer = PeerInfo(
            iface="wg0",
            pubkey="A" * 43 + "=",
            endpoint="1.2.3.4:51820",
            allowed_ips="10.0.0.1/32",
            last_handshake=1678888888,
            is_online=True,
        )

    @patch("wg_monitor.subprocess.run")
    @patch("wg_monitor.Path.is_file", return_value=True)
    @patch("wg_monitor.os.access", return_value=True)
    def test_script_called_with_env_vars(
        self, mock_access: Any, mock_is_file: Any, mock_run: Any
    ) -> None:
        monitor = _make_monitor(on_change_script="/usr/local/bin/notify.sh")
        monitor._run_on_change_script(self.peer, "ONLINE")

        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args[1]
        env = call_kwargs["env"]
        self.assertEqual(env["PEER_EVENT"], "ONLINE")
        self.assertEqual(env["PEER_IFACE"], "wg0")
        self.assertEqual(env["PEER_PUBKEY"], self.peer.pubkey)
        self.assertEqual(env["PEER_ENDPOINT"], "1.2.3.4:51820")
        self.assertEqual(env["PEER_ALLOWED_IPS"], "10.0.0.1")
        self.assertEqual(env["PEER_HANDSHAKE"], "1678888888")
        self.assertEqual(env["PEER_ONLINE"], "1")

        call_args_pos = mock_run.call_args[0]
        self.assertEqual(call_args_pos[0], ["/usr/local/bin/notify.sh"])

    @patch("wg_monitor.subprocess.run")
    def test_script_not_called_when_none(self, mock_run: Any) -> None:
        monitor = _make_monitor(on_change_script=None)
        monitor._run_on_change_script(self.peer, "ONLINE")
        mock_run.assert_not_called()


class TestRoamingDetection(unittest.TestCase):
    def setUp(self) -> None:
        self.monitor = _make_monitor()
        self.pubkey = "A" * 43 + "="
        self.iface = "wg0"
        self.peer_key = (self.iface, self.pubkey)

    def test_roaming_detected(self) -> None:
        peer_old = PeerInfo(
            self.iface, self.pubkey, "1.1.1.1:51820",
            "10.0.0.1/32", int(time.time()) - 10, True,
        )
        peer_new = PeerInfo(
            self.iface, self.pubkey, "2.2.2.2:51820",
            "10.0.0.1/32", int(time.time()) - 5, True,
        )

        self.monitor.peer_states[self.peer_key] = peer_old

        last_peer = self.monitor.peer_states[self.peer_key]
        self.assertTrue(last_peer.is_online)
        self.assertTrue(peer_new.is_online)
        self.assertNotEqual(last_peer.endpoint, peer_new.endpoint)

        self.monitor.peer_states[self.peer_key] = peer_new
        self.assertEqual(
            self.monitor.peer_states[self.peer_key].endpoint, "2.2.2.2:51820"
        )


class TestRemovedDetection(unittest.TestCase):
    def setUp(self) -> None:
        self.monitor = _make_monitor()
        self.pubkey = "A" * 43 + "="
        self.iface = "wg0"
        self.peer_key = (self.iface, self.pubkey)

    def test_removed_peer(self) -> None:
        peer = PeerInfo(
            self.iface, self.pubkey, "1.1.1.1:51820",
            "10.0.0.1/32", 1678888888, True,
        )
        self.monitor.peer_states[self.peer_key] = peer

        seen_keys: set[tuple[str, str]] = set()
        removed_keys = set(self.monitor.peer_states.keys()) - seen_keys
        self.assertIn(self.peer_key, removed_keys)

        for key in removed_keys:
            removed_peer = self.monitor.peer_states.pop(key)
            self.assertEqual(removed_peer, peer)

        self.assertNotIn(self.peer_key, self.monitor.peer_states)


class TestValidateConfigInterface(unittest.TestCase):
    def test_invalid_interface_exits(self) -> None:
        monitor = _make_monitor(interface="invalid!@#name")
        with self.assertRaises(SystemExit):
            monitor._validate_config()

    @patch.object(WireGuardMonitor, "_verify_interface")
    def test_valid_interface_kept(self, mock_verify: Any) -> None:
        monitor = _make_monitor(interface="wg0")
        monitor._validate_config()
        self.assertEqual(monitor.interface, "wg0")
        mock_verify.assert_called_once_with("wg0")

    def test_interface_too_long_exits(self) -> None:
        monitor = _make_monitor(interface="a" * 16)
        with self.assertRaises(SystemExit):
            monitor._validate_config()

    @patch.object(WireGuardMonitor, "_verify_interface")
    def test_interface_with_hyphen_underscore(self, mock_verify: Any) -> None:
        monitor = _make_monitor(interface="wg-test_0")
        monitor._validate_config()
        self.assertEqual(monitor.interface, "wg-test_0")

    @patch("wg_monitor.subprocess.run")
    def test_verify_interface_not_found_exits(self, mock_run: Any) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "Unable to access interface: No such device"
        mock_run.return_value = mock_result
        monitor = _make_monitor(interface="wg99")
        with self.assertRaises(SystemExit):
            monitor._verify_interface("wg99")

    @patch("wg_monitor.subprocess.run")
    def test_verify_interface_success(self, mock_run: Any) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_run.return_value = mock_result
        monitor = _make_monitor(interface="wg0")
        monitor._verify_interface("wg0")


class TestResolveWgPath(unittest.TestCase):
    @patch("wg_monitor.shutil.which", return_value="/usr/bin/wg")
    def test_wg_found(self, mock_which: Any) -> None:
        monitor = _make_monitor()
        result = monitor._resolve_wg_path()
        self.assertEqual(result, "/usr/bin/wg")
        mock_which.assert_called_once_with("wg", path="/usr/bin:/usr/sbin:/bin:/sbin")

    @patch("wg_monitor.shutil.which", return_value=None)
    def test_wg_not_found_exits(self, mock_which: Any) -> None:
        monitor = _make_monitor()
        with self.assertRaises(SystemExit):
            monitor._resolve_wg_path()


if __name__ == "__main__":
    unittest.main()
