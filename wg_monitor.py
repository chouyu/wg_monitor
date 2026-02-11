#!/usr/bin/env python3
"""
WireGuard Peer Status Monitor

A production-grade monitoring tool that tracks WireGuard peer connectivity status
by analyzing handshake timestamps. Provides state change alerts
and persistent audit logs.

Requirements:
    - Python 3.7+
    - WireGuard installed with 'wg' command available
    - Root privileges

Example:
    sudo python3 wg_monitor.py --interval 60 --threshold 300 --debug

Security:
    - Input validation on all external data
    - Path traversal protection
    - Log injection prevention
"""

import argparse
import datetime
import logging
import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import Any, Dict, Optional, Set, Tuple

# 默认配置
DEFAULT_LOG_PATH = "/var/log/wg_monitor.log"
DEFAULT_CHECK_INTERVAL = 30
DEFAULT_OFFLINE_THRESHOLD = 180
DEFAULT_STATS_INTERVAL = 3600

# 安全常量
VALID_LOG_PATHS = ["/var/log", "/tmp", "./logs"]  # 允许的日志目录
WG_PUBKEY_PATTERN = re.compile(r"^[A-Za-z0-9+/]{43}=$")  # WireGuard 公钥格式
WG_IFACE_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,15}$")  # WireGuard 接口名格式
MAX_ENDPOINT_LENGTH = 255
MAX_PEERS_TRACKED = 10000  # 防止内存无限增长

LOG_FORMAT = "%(asctime)s %(leveltag)s%(message)s"
LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"

LEVEL_TAGS: Dict[int, str] = {
    logging.DEBUG: "[DEBUG] ",
    logging.INFO: "",
    logging.WARNING: "[WARN] ",
    logging.ERROR: "[ERROR] ",
    logging.CRITICAL: "[CRIT] ",
}


class CompactFormatter(logging.Formatter):
    """INFO 级别省略标签，其余级别显示短标签"""

    def format(self, record: logging.LogRecord) -> str:
        record.leveltag = LEVEL_TAGS.get(record.levelno, f"[{record.levelname}] ")
        return super().format(record)


@dataclass
class PeerInfo:
    """WireGuard Peer 的状态数据，由 _parse_line 解析 wg dump 输出生成"""

    iface: str
    pubkey: str
    endpoint: str
    allowed_ips: str
    last_handshake: int
    is_online: bool

    @property
    def sanitized_endpoint(self) -> str:
        """返回安全的 endpoint 字符串（防止日志注入）"""
        if not self.endpoint:
            return "N/A"
        # 移除换行符和控制字符
        safe_endpoint = "".join(c for c in self.endpoint if c.isprintable())
        return safe_endpoint[:MAX_ENDPOINT_LENGTH]

    @property
    def sanitized_allowed_ips(self) -> str:
        """返回安全的 AllowedIPs 字符串

        优先返回 /32 (IPv4) 和 /128 (IPv6) 主机地址。
        如果不存在主机地址，则返回所有 IP（作为 fallback）。
        """
        if not self.allowed_ips:
            return "N/A"

        # 简单清洗
        safe_ips_str = "".join(c for c in self.allowed_ips if c.isprintable())

        # 分割 IP 列表
        ips = [ip.strip() for ip in safe_ips_str.split(",")]

        # 筛选主机 IP (/32, /128)
        host_ips = [ip for ip in ips if ip.endswith("/32") or ip.endswith("/128")]

        if host_ips:
            # 去除 CIDR 后缀 (/32, /128) 使其看起来像纯 IP
            cleaned_host_ips = [ip.split("/")[0] for ip in host_ips]
            return ", ".join(cleaned_host_ips)[:1024]

        # Fallback: 如果没有主机 IP，返回所有（可能是路由模式）
        return safe_ips_str[:1024]

    @property
    def sanitized_pubkey(self) -> str:
        """返回截断的公钥（防止日志过长）"""
        if len(self.pubkey) >= 16:
            return f"{self.pubkey[:8]}...{self.pubkey[-8:]}"
        return self.pubkey


class WireGuardMonitor:
    """WireGuard Peer 状态监控器"""

    def __init__(
        self,
        log_path: str,
        interval: int,
        threshold: int,
        stats_interval: int,
        debug: bool,
    ):
        self.interval = interval
        self.threshold = threshold
        self.stats_interval = stats_interval
        self.running = True
        self.peer_states: Dict[Tuple[str, str], PeerInfo] = {}  # key: (iface, pubkey)
        self._stop_event = Event()
        self._wg_not_found_logged = False

        # 统计信息
        self.stats = {
            "total_checks": 0,
            "failed_checks": 0,
            "state_changes": 0,
            "parse_errors": 0,
        }

        # 验证并初始化日志
        validated_log_path = self._validate_log_path(log_path)
        self._setup_logging(validated_log_path, debug)

        # 验证配置
        self._validate_config()

        # 保存日志配置用于 reopen
        self._log_path = validated_log_path
        self._debug = debug

        # 注册信号处理
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGHUP, self._sighup_handler)

    def _sighup_handler(self, signum: int, frame: Any) -> None:
        """处理 SIGHUP 信号，重新打开日志文件（用于 logrotate）"""
        self.logger.info("Received SIGHUP, reopening log file...")
        self._reopen_log_file()
        self.logger.info("Log file reopened successfully.")

    def _reopen_log_file(self) -> None:
        """原子替换文件 handler，避免竞态丢失日志"""
        logger = self.logger
        formatter = CompactFormatter(LOG_FORMAT, datefmt=LOG_DATEFMT)
        try:
            new_handler = logging.FileHandler(
                self._log_path, encoding="utf-8"
            )
            new_handler.setFormatter(formatter)
        except OSError as e:
            logger.error(f"Failed to reopen log file: {e}")
            return

        old_handlers = [
            h for h in logger.handlers if isinstance(h, logging.FileHandler)
        ]
        logger.addHandler(new_handler)
        for h in old_handlers:
            logger.removeHandler(h)
            h.close()

    def _validate_log_path(self, log_path: str) -> str:
        """验证日志路径，防止路径遍历攻击"""
        try:
            # 规范化路径
            path = Path(log_path).resolve()
            parent_dir = path.parent

            # 检查父目录是否在允许列表中
            allowed = False
            for allowed_path in VALID_LOG_PATHS:
                try:
                    allowed_parent = Path(allowed_path).resolve()
                    if parent_dir == allowed_parent or parent_dir.is_relative_to(
                        allowed_parent
                    ):
                        allowed = True
                        break
                except (ValueError, AttributeError):
                    # Python < 3.9 没有 is_relative_to，回退到字符串比较
                    if str(parent_dir).startswith(str(Path(allowed_path).resolve())):
                        allowed = True
                        break

            if not allowed:
                sys.stderr.write(
                    f"Error: Log path {log_path} is not in allowed directories: "
                    f"{VALID_LOG_PATHS}\n"
                )
                sys.stderr.write(f"Using default: {DEFAULT_LOG_PATH}\n")
                return DEFAULT_LOG_PATH

            # 确保父目录存在
            parent_dir.mkdir(parents=True, exist_ok=True)

            return str(path)

        except (ValueError, OSError) as e:
            sys.stderr.write(
                f"Error validating log path: {e}. Using default: {DEFAULT_LOG_PATH}\n"
            )
            return DEFAULT_LOG_PATH

    def _setup_logging(self, log_path: str, debug: bool) -> None:
        """配置日志系统（轮转由外部 logrotate 管理）"""
        level = logging.DEBUG if debug else logging.INFO
        logger = logging.getLogger("WGMonitor")
        logger.setLevel(level)

        for h in list(logger.handlers):
            logger.removeHandler(h)
            h.close()

        formatter = CompactFormatter(LOG_FORMAT, datefmt=LOG_DATEFMT)

        try:
            file_handler = logging.FileHandler(
                log_path, encoding="utf-8"
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except PermissionError:
            sys.stderr.write(
                f"Error: No permission to write to {log_path}. "
                "Run as root or change path.\n"
            )
            sys.exit(1)
        except OSError as e:
            sys.stderr.write(f"Error: Cannot create log file {log_path}: {e}\n")
            sys.exit(1)

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        self.logger = logger

    def _validate_config(self) -> None:
        """验证配置参数"""
        if self.interval < 5:
            self.logger.warning("Interval too small (<5s), setting to 5s")
            self.interval = 5

        if self.interval > 3600:
            self.logger.warning(
                "Interval very large (>1h), this may delay issue detection"
            )

        if self.threshold < self.interval:
            self.logger.warning(
                f"Threshold ({self.threshold}s) < Interval ({self.interval}s), "
                "may cause false offline alerts"
            )

        if self.threshold < 60:
            self.logger.warning(
                "Threshold <60s may be too sensitive for unstable networks"
            )

        if self.stats_interval < 60:
            self.logger.warning("Stats interval too small (<60s), setting to 60s")
            self.stats_interval = 60

    def _signal_handler(self, signum: int, frame: Any) -> None:
        """处理退出信号"""
        self.logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.running = False
        self._stop_event.set()

    def _fetch_dump(self) -> str:
        """执行 wg 命令并获取输出"""
        try:
            # 复制当前环境并仅限制 PATH，保留 LC_ALL/LANG 等
            env = os.environ.copy()
            env["PATH"] = "/usr/bin:/usr/sbin:/bin:/sbin"

            result = subprocess.run(
                ["wg", "show", "all", "dump"],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
                env=env,
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            self.logger.error("Command 'wg show all dump' timed out after 10s")
        except subprocess.CalledProcessError as e:
            self.logger.error(
                f"Command failed with return code {e.returncode}: {e.stderr}"
            )
        except FileNotFoundError:
            if not self._wg_not_found_logged:
                self.logger.critical("Command 'wg' not found. Is WireGuard installed?")
                self._wg_not_found_logged = True
                self.running = False
        except Exception:
            self.logger.exception("Unexpected error executing command")
        return ""

    def _parse_line(self, line: str) -> Optional[PeerInfo]:
        """解析单行数据，包含严格的安全验证"""
        try:
            parts = line.split("\t")

            # wg show all dump 格式：
            # 接口行: interface_name, private_key, public_key, listen_port, fwmark
            # Peer 行: interface_name, public_key, preshared_key, endpoint, allowed_ips,
            #         latest_handshake, transfer_rx, transfer_tx, persistent_keepalive

            # 过滤接口配置行（通常 5 个字段）
            if len(parts) < 9:
                return None

            iface = parts[0]
            pubkey = parts[1]
            endpoint = parts[3]
            allowed_ips = parts[4]

            if not WG_IFACE_PATTERN.match(iface):
                self.logger.debug(f"Invalid iface name, skipping: {iface[:20]}")
                return None

            if not WG_PUBKEY_PATTERN.match(pubkey):
                self.logger.debug(f"Invalid pubkey format, skipping: {pubkey[:20]}...")
                return None

            # 解析握手时间戳
            try:
                last_handshake = int(parts[5])
                if last_handshake < 0:
                    self.logger.warning(
                        f"Negative handshake timestamp for {pubkey[:16]}..., "
                        "treating as 0"
                    )
                    last_handshake = 0
            except (ValueError, IndexError):
                self.logger.warning(
                    f"Failed to parse handshake timestamp: {line[:50]}..."
                )
                self.stats["parse_errors"] += 1
                return None

            current_time = int(time.time())
            if last_handshake <= 0:
                is_online = False
            else:
                is_online = (current_time - last_handshake) < self.threshold

            return PeerInfo(
                iface=iface,
                pubkey=pubkey,
                endpoint=endpoint,
                allowed_ips=allowed_ips,
                last_handshake=last_handshake,
                is_online=is_online,
            )

        except (IndexError, ValueError) as e:
            self.logger.warning(f"Parse error: {e}")
            self.stats["parse_errors"] += 1
            return None

    def _format_peer_info(self, peer: PeerInfo) -> str:
        """格式化 Peer 信息用于日志输出"""
        ips = peer.sanitized_allowed_ips
        label = "IP" if "," not in ips and "/" not in ips else "IPs"
        return (
            f"[{peer.iface}] {peer.sanitized_pubkey} "
            f"({peer.sanitized_endpoint}) [{label}: {ips}]"
        )

    def _format_handshake_time(self, timestamp: int) -> str:
        """格式化握手时间，当天只显示时分秒，跨天显示完整日期"""
        if timestamp <= 0:
            return "Never"
        try:
            dt = datetime.datetime.fromtimestamp(timestamp)
            today = datetime.date.today()
            if dt.date() == today:
                return dt.strftime("%H:%M:%S")
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, OSError):
            return "Invalid"

    def _print_stats(self) -> None:
        """打印监控统计信息（仅输出到控制台/journal，不写入日志文件）"""
        msg = (
            f"Statistics | Checks: {self.stats['total_checks']}, "
            f"Failures: {self.stats['failed_checks']}, "
            f"Changes: {self.stats['state_changes']}, "
            f"Errors: {self.stats['parse_errors']}, "
            f"Peers: {len(self.peer_states)}"
        )
        record = self.logger.makeRecord(
            self.logger.name, logging.INFO, "", 0, msg, (), None
        )
        for handler in self.logger.handlers:
            if not isinstance(handler, logging.FileHandler):
                handler.emit(record)

    def _check_peer_limit(self) -> bool:
        """检查追踪的 peer 数量，防止内存耗尽"""
        if len(self.peer_states) >= MAX_PEERS_TRACKED:
            self.logger.error(
                f"Reached maximum tracked peers limit ({MAX_PEERS_TRACKED}). "
                "Possible memory leak or misconfiguration."
            )
            return False
        return True

    def run(self) -> None:
        """主监控循环"""
        self.logger.info(
            f"Monitor started | Interval: {self.interval}s, "
            f"Threshold: {self.threshold}s, Stats: {self.stats_interval}s"
        )

        last_stats_time = time.time()

        while self.running:
            loop_start = time.time()
            self.stats["total_checks"] += 1

            if not self._check_peer_limit():
                self.running = False
                break

            raw_output = self._fetch_dump()

            if not raw_output:
                self.stats["failed_checks"] += 1
                self._stop_event.wait(timeout=self.interval)
                continue

            seen_keys: Set[Tuple[str, str]] = set()

            for line in raw_output.strip().split("\n"):
                if not line.strip():
                    continue

                peer = self._parse_line(line)
                if not peer:
                    continue

                peer_key = (peer.iface, peer.pubkey)
                seen_keys.add(peer_key)
                is_online = peer.is_online

                if peer_key not in self.peer_states:
                    self.peer_states[peer_key] = peer
                    tag = "ONLINE " if is_online else "OFFLINE"
                    hs = self._format_handshake_time(peer.last_handshake)
                    self.logger.info(
                        f"{tag} {self._format_peer_info(peer)}"
                        f" new (handshake: {hs})",
                    )

                else:
                    last_peer = self.peer_states[peer_key]
                    last_is_online = last_peer.is_online

                    if last_is_online != is_online:
                        self.stats["state_changes"] += 1
                        tag = "ONLINE " if is_online else "OFFLINE"
                        hs = self._format_handshake_time(peer.last_handshake)
                        self.logger.info(
                            f"{tag} {self._format_peer_info(peer)}"
                            f" (handshake: {hs})",
                        )

                    elif is_online and last_peer.endpoint != peer.endpoint:
                        self.logger.info(
                            f"ROAMING {self._format_peer_info(peer)}"
                            f" {last_peer.sanitized_endpoint}"
                            f" → {peer.sanitized_endpoint}"
                        )

                    self.peer_states[peer_key] = peer

            removed_keys = set(self.peer_states.keys()) - seen_keys
            for key in removed_keys:
                removed_peer = self.peer_states.pop(key)
                hs = self._format_handshake_time(
                    removed_peer.last_handshake
                )
                self.logger.warning(
                    f"REMOVED {self._format_peer_info(removed_peer)}"
                    f" (handshake: {hs})"
                )
                self.stats["state_changes"] += 1

            current_time = time.time()
            if current_time - last_stats_time >= self.stats_interval:
                self._print_stats()
                last_stats_time = current_time

            elapsed = time.time() - loop_start
            sleep_time = max(0, self.interval - elapsed)
            self._stop_event.wait(timeout=sleep_time)

        self.logger.info("Monitor stopped gracefully.")
        self._print_stats()


def check_root() -> None:
    """检查是否以 root 权限运行"""
    if os.geteuid() != 0:
        sys.stderr.write(
            "Error: This script requires root privileges to run 'wg show'.\n"
        )
        sys.stderr.write("Please run with sudo or as root user.\n")
        sys.exit(1)


def parse_arguments() -> argparse.Namespace:
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description="WireGuard Peer Status Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage with defaults
  sudo python3 wg_monitor.py

  # Custom intervals and debug mode
  sudo python3 wg_monitor.py --interval 60 --threshold 300 --debug

  # Custom log path
  sudo python3 wg_monitor.py --log-path /var/log/custom_wg.log

Security notes:
  - Log paths are restricted to predefined directories
  - All external inputs are validated and sanitized
  - Runs with minimal required privileges
        """,
    )

    parser.add_argument(
        "--log-path",
        default=DEFAULT_LOG_PATH,
        help=f"Path to log file (default: {DEFAULT_LOG_PATH})",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_CHECK_INTERVAL,
        help=f"Check interval in seconds (default: {DEFAULT_CHECK_INTERVAL})",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_OFFLINE_THRESHOLD,
        help=(
            "Seconds without handshake to consider offline "
            f"(default: {DEFAULT_OFFLINE_THRESHOLD})"
        ),
    )
    parser.add_argument(
        "--stats-interval",
        type=int,
        default=DEFAULT_STATS_INTERVAL,
        help=(
            f"Statistics report interval in seconds (default: {DEFAULT_STATS_INTERVAL})"
        ),
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--version", action="version", version="WireGuard Monitor v2.0.0"
    )

    return parser.parse_args()


def main() -> None:
    """主入口函数"""
    check_root()
    args = parse_arguments()

    try:
        monitor = WireGuardMonitor(
            log_path=args.log_path,
            interval=args.interval,
            threshold=args.threshold,
            stats_interval=args.stats_interval,
            debug=args.debug,
        )
        monitor.run()
    except KeyboardInterrupt:
        print("\nMonitor interrupted by user")
        sys.exit(0)
    except Exception as e:
        if not logging.getLogger().handlers:
            logging.basicConfig(level=logging.ERROR)
        logging.exception(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
