import time
import unittest
from unittest.mock import MagicMock, patch

import pytest

from wg_monitor import PeerInfo, WireGuardMonitor


def _make_monitor() -> WireGuardMonitor:
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
        )
    monitor.logger = MagicMock()
    return monitor


VALID_PUBKEY = "A" * 43 + "="


class TestParser(unittest.TestCase):
    def setUp(self) -> None:
        self.monitor = _make_monitor()

    def test_parse_valid_peer(self) -> None:
        line = (
            f"wg0\t{VALID_PUBKEY}\t(none)\t192.168.1.100:51820\t10.0.0.2/32"
            "\t1678888888\t1024\t2048\t25"
        )

        peer = self.monitor._parse_line(line)

        self.assertIsNotNone(peer)
        assert peer is not None
        self.assertEqual(peer.iface, "wg0")
        self.assertEqual(peer.pubkey, VALID_PUBKEY)
        self.assertEqual(peer.allowed_ips, "10.0.0.2/32")
        self.assertEqual(peer.endpoint, "192.168.1.100:51820")
        self.assertEqual(peer.last_handshake, 1678888888)

    def test_parse_interface_line_ignored(self) -> None:
        line = "wg0\tPRIVATE_KEY\tPUBLIC_KEY\t51820\toff"

        peer = self.monitor._parse_line(line)
        self.assertIsNone(peer)

    def test_parse_invalid_pubkey(self) -> None:
        line = "wg0\tShortKey\t(none)\t1.1.1.1:123\t10.0.0.2/32\t1678888888\t0\t0\t0"

        peer = self.monitor._parse_line(line)
        self.assertIsNone(peer)

    def test_parse_invalid_handshake(self) -> None:
        line = (
            f"wg0\t{VALID_PUBKEY}\t(none)\t1.1.1.1:123\t10.0.0.2/32"
            "\tINVALID_TIME\t0\t0\t0"
        )

        peer = self.monitor._parse_line(line)
        self.assertIsNone(peer)
        self.monitor.logger.warning.assert_called()  # type: ignore
        self.assertEqual(self.monitor.stats.parse_errors, 1)

    def test_parse_negative_handshake(self) -> None:
        line = f"wg0\t{VALID_PUBKEY}\t(none)\t1.1.1.1:123\t10.0.0.2/32\t-12345\t0\t0\t0"

        peer = self.monitor._parse_line(line)
        self.assertIsNotNone(peer)

        assert peer is not None
        self.assertEqual(peer.last_handshake, 0)

    def test_is_online_logic(self) -> None:
        now = int(time.time())
        threshold = 180

        line_online = (
            f"wg0\t{VALID_PUBKEY}\t(none)\tep\t10.0.0.1/32\t{now - 10}\t0\t0\t0"
        )
        peer_online = self.monitor._parse_line(line_online)
        assert peer_online is not None
        self.assertTrue(peer_online.is_online)

        hs_old = now - threshold - 1
        line_offline = (
            f"wg0\t{VALID_PUBKEY}\t(none)\tep\t10.0.0.1/32\t{hs_old}\t0\t0\t0"
        )
        peer_offline = self.monitor._parse_line(line_offline)
        assert peer_offline is not None
        self.assertFalse(peer_offline.is_online)

        line_never = f"wg0\t{VALID_PUBKEY}\t(none)\tep\t10.0.0.1/32\t0\t0\t0\t0"
        peer_never = self.monitor._parse_line(line_never)
        assert peer_never is not None
        self.assertFalse(peer_never.is_online)

    def test_parse_allowed_ips_filtering(self) -> None:
        peer = PeerInfo(
            "wg0", "key", "ep", "10.0.0.1/32, 192.168.1.0/24", 0, False
        )
        self.assertEqual(peer.sanitized_allowed_ips, "10.0.0.1")

        peer = PeerInfo(
            "wg0", "key", "ep", "192.168.1.0/24, 172.16.0.0/12", 0, False
        )
        self.assertEqual(peer.sanitized_allowed_ips, "192.168.1.0/24, 172.16.0.0/12")

        peer = PeerInfo("wg0", "key", "ep", "fd00::1/128, fd00::/64", 0, False)
        self.assertEqual(peer.sanitized_allowed_ips, "fd00::1")

        peer = PeerInfo("wg0", "key", "ep", "(none)", 0, False)
        self.assertEqual(peer.sanitized_allowed_ips, "(none)")


# ---------------------------------------------------------------------------
# Parametrized _parse_line edge case tests
# ---------------------------------------------------------------------------

def _build_peer_line(
    iface: str = "wg0",
    pubkey: str = VALID_PUBKEY,
    preshared: str = "(none)",
    endpoint: str = "1.1.1.1:51820",
    allowed_ips: str = "10.0.0.1/32",
    handshake: str = "1678888888",
    rx: str = "0",
    tx: str = "0",
    keepalive: str = "0",
) -> str:
    return "\t".join([
        iface, pubkey, preshared, endpoint, allowed_ips,
        handshake, rx, tx, keepalive,
    ])


@pytest.fixture
def monitor() -> WireGuardMonitor:
    return _make_monitor()


@pytest.mark.parametrize(
    "line,expected_none,description",
    [
        pytest.param("", True, "empty line"),
        pytest.param("wg0\tonly\ttwo", True, "too few fields"),
        pytest.param(
            "wg0\tPRIVATE_KEY\tPUBLIC_KEY\t51820\toff",
            True,
            "interface line",
        ),
        pytest.param(
            _build_peer_line(handshake="0"),
            False,
            "valid peer with handshake=0 (never connected)",
        ),
        pytest.param(
            _build_peer_line(handshake=str(int(time.time()) + 86400)),
            False,
            "valid peer with future handshake timestamp",
        ),
    ],
)
def test_parse_line_edge_cases(
    monitor: WireGuardMonitor,
    line: str,
    expected_none: bool,
    description: str,
) -> None:
    result = monitor._parse_line(line)
    if expected_none:
        assert result is None, f"Expected None for: {description}"
    else:
        assert result is not None, f"Expected PeerInfo for: {description}"


def test_handshake_zero_is_offline(monitor: WireGuardMonitor) -> None:
    line = _build_peer_line(handshake="0")
    peer = monitor._parse_line(line)
    assert peer is not None
    assert not peer.is_online


def test_future_handshake_is_online(monitor: WireGuardMonitor) -> None:
    future_ts = str(int(time.time()) + 86400)
    line = _build_peer_line(handshake=future_ts)
    peer = monitor._parse_line(line)
    assert peer is not None
    assert peer.is_online


def test_parse_errors_stat_incremented(monitor: WireGuardMonitor) -> None:
    line = _build_peer_line(handshake="NOT_A_NUMBER")
    assert monitor.stats.parse_errors == 0
    monitor._parse_line(line)
    assert monitor.stats.parse_errors == 1


if __name__ == "__main__":
    unittest.main()
