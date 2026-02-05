import unittest
import time
import logging
from unittest.mock import MagicMock, patch
from wg_monitor import WireGuardMonitor, PeerInfo


class TestParser(unittest.TestCase):
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

    def test_parse_valid_peer(self):
        # 43 chars + '=' = 44 chars
        valid_pubkey = "A" * 43 + "="
        line = f"wg0\t{valid_pubkey}\t(none)\t192.168.1.100:51820\t10.0.0.2/32\t1678888888\t1024\t2048\t25"

        peer = self.monitor._parse_line(line)

        self.assertIsNotNone(peer)
        assert peer is not None  # for mypy
        self.assertEqual(peer.iface, "wg0")
        self.assertEqual(peer.pubkey, valid_pubkey)

        self.assertEqual(peer.endpoint, "192.168.1.100:51820")
        self.assertEqual(peer.last_handshake, 1678888888)

    def test_parse_interface_line_ignored(self):
        line = "wg0\tPRIVATE_KEY\tPUBLIC_KEY\t51820\toff"

        peer = self.monitor._parse_line(line)
        self.assertIsNone(peer)

    def test_parse_invalid_pubkey(self):
        line = "wg0\tShortKey\t(none)\t1.1.1.1:123\t10.0.0.2/32\t1678888888\t0\t0\t0"

        peer = self.monitor._parse_line(line)
        self.assertIsNone(peer)

    def test_parse_invalid_handshake(self):
        valid_pubkey = "A" * 43 + "="
        line = f"wg0\t{valid_pubkey}\t(none)\t1.1.1.1:123\t10.0.0.2/32\tINVALID_TIME\t0\t0\t0"

        peer = self.monitor._parse_line(line)
        self.assertIsNone(peer)
        self.monitor.logger.warning.assert_called()  # type: ignore

    def test_parse_negative_handshake(self):
        valid_pubkey = "A" * 43 + "="
        line = f"wg0\t{valid_pubkey}\t(none)\t1.1.1.1:123\t10.0.0.2/32\t-12345\t0\t0\t0"

        peer = self.monitor._parse_line(line)
        self.assertIsNotNone(peer)

        assert peer is not None
        self.assertEqual(peer.last_handshake, 0)

    def test_is_online_logic(self):
        now = int(time.time())
        threshold = 180

        peer_online = PeerInfo("wg0", "key", "ep", now - 10, threshold)
        self.assertTrue(peer_online.is_online)

        peer_offline = PeerInfo("wg0", "key", "ep", now - threshold - 1, threshold)
        self.assertFalse(peer_offline.is_online)

        peer_never = PeerInfo("wg0", "key", "ep", 0, threshold)
        self.assertFalse(peer_never.is_online)


if __name__ == "__main__":
    unittest.main()
