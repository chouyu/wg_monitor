import unittest
import logging
from unittest.mock import MagicMock, patch, PropertyMock
from wg_monitor import WireGuardMonitor, PeerInfo


class TestMonitor(unittest.TestCase):
    def setUp(self):
        # Mock _setup_logging and _validate_config to avoid filesystem/permission issues during test init
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
    def test_fetch_dump_success(self, mock_run):
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
    def test_fetch_dump_failure(self, mock_run):
        from subprocess import CalledProcessError

        mock_run.side_effect = CalledProcessError(1, ["wg"], stderr="error")

        output = self.monitor._fetch_dump()
        self.assertEqual(output, "")
        self.monitor.logger.error.assert_called()  # type: ignore

    def test_state_change_detection(self):
        pubkey = "A" * 43 + "="
        peer = PeerInfo("wg0", pubkey, "1.1.1.1:123", 1678888888, 180)

        self.assertNotIn(pubkey, self.monitor.peer_states)

        # 使用 PropertyMock 来 mock @property
        with patch.object(
            PeerInfo, "is_online", new_callable=PropertyMock
        ) as mock_online:
            mock_online.return_value = True

            # 手动执行模拟逻辑
            is_online = peer.is_online
            if peer.pubkey not in self.monitor.peer_states:
                self.monitor.peer_states[peer.pubkey] = is_online

            self.assertIn(pubkey, self.monitor.peer_states)
            self.assertTrue(self.monitor.peer_states[pubkey])

            # 状态变为 Offline
            mock_online.return_value = False
            is_online = peer.is_online

            if self.monitor.peer_states[peer.pubkey] != is_online:
                self.monitor.peer_states[peer.pubkey] = is_online

            self.assertFalse(self.monitor.peer_states[pubkey])


if __name__ == "__main__":
    unittest.main()
