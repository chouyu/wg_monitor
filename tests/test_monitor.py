import unittest
from typing import Any
from unittest.mock import MagicMock, patch

from wg_monitor import PeerInfo, WireGuardMonitor


class TestMonitor(unittest.TestCase):
    def setUp(self) -> None:
        # Mock _setup_logging and _validate_config to avoid filesystem/permission issues
        # during test init
        with patch.object(WireGuardMonitor, "_setup_logging"), patch.object(
            WireGuardMonitor, "_validate_config"
        ), patch.object(
            WireGuardMonitor, "_validate_log_path", return_value="/dev/null"
        ):
            self.monitor = WireGuardMonitor(
                log_path="/dev/null",
                interval=30,
                threshold=180,
                stats_interval=3600,
                debug=True,
            )

        # Manually attach a mock logger since _setup_logging was skipped
        self.monitor.logger = MagicMock()

    @patch("wg_monitor.subprocess.run")
    def test_fetch_dump_success(self, mock_run: Any) -> None:
        mock_result = MagicMock()
        mock_result.stdout = "mock output"
        mock_run.return_value = mock_result

        output = self.monitor._fetch_dump()
        self.assertEqual(output, "mock output")

        call_args = mock_run.call_args
        self.assertIn("env", call_args[1])
        env = call_args[1]["env"]
        self.assertIn("PATH", env)
        self.assertEqual(env["PATH"], "/usr/bin:/usr/sbin:/bin:/sbin")

        import os

        if "HOME" in os.environ:
            self.assertEqual(env["HOME"], os.environ["HOME"])

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


if __name__ == "__main__":
    unittest.main()
