#!/usr/bin/env python3
"""
WireGuard Peer Status Monitor

A production-grade monitoring tool that tracks WireGuard peer connectivity status
by analyzing handshake timestamps. Provides state change alerts and rotating logs.

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

import subprocess
import time
import datetime
import logging
import argparse
import signal
import sys
import os
import re
from pathlib import Path
from logging.handlers import RotatingFileHandler
from dataclasses import dataclass
from typing import Dict, Optional
from threading import Event

# 默认配置
DEFAULT_LOG_PATH = "/var/log/wg_monitor.log"
DEFAULT_CHECK_INTERVAL = 30
DEFAULT_OFFLINE_THRESHOLD = 180
DEFAULT_STATS_INTERVAL = 3600

# 安全常量
VALID_LOG_PATHS = ["/var/log", "/tmp", "./logs"]  # 允许的日志目录
WG_PUBKEY_PATTERN = re.compile(r"^[A-Za-z0-9+/]{43}=$")  # WireGuard 公钥格式
MAX_ENDPOINT_LENGTH = 255
MAX_PEERS_TRACKED = 10000  # 防止内存无限增长


@dataclass
class PeerInfo:
    """定义 Peer 数据结构，提高代码可读性"""

    iface: str
    pubkey: str
    endpoint: str
    allowed_ips: str  # 新增
    last_handshake: int
    threshold: int

    @property
    def is_online(self) -> bool:
        """判断在线状态逻辑封装"""
        if self.last_handshake <= 0:
            return False
        current_time = int(time.time())
        time_since_handshake = current_time - self.last_handshake
        return time_since_handshake < self.threshold

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
        self.peer_states: Dict[str, PeerInfo] = {}  # 改为存储 PeerInfo 对象以对比状态
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

        # 注册信号处理
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

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
                    f"Error: Log path {log_path} is not in allowed directories: {VALID_LOG_PATHS}\n"
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
        """配置带有轮转功能的日志系统"""
        level = logging.DEBUG if debug else logging.INFO
        logger = logging.getLogger("WGMonitor")
        logger.setLevel(level)

        # 防止重复添加 handler
        if logger.handlers:
            logger.handlers.clear()

        formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )

        # 文件处理器：最大 10MB，保留 5 个备份
        try:
            file_handler = RotatingFileHandler(
                log_path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except PermissionError:
            sys.stderr.write(
                f"Error: No permission to write to {log_path}. Run as root or change path.\n"
            )
            sys.exit(1)
        except OSError as e:
            sys.stderr.write(f"Error: Cannot create log file {log_path}: {e}\n")
            sys.exit(1)

        # 控制台输出

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

    def _signal_handler(self, signum: int, frame) -> None:
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
            allowed_ips = parts[4]  # 解析 AllowedIPs

            # 验证公钥格式
            if not WG_PUBKEY_PATTERN.match(pubkey):
                self.logger.debug(f"Invalid pubkey format, skipping: {pubkey[:20]}...")
                return None

            # 解析握手时间戳
            try:
                last_handshake = int(parts[5])
                if last_handshake < 0:
                    self.logger.warning(
                        f"Negative handshake timestamp for {pubkey[:16]}..., treating as 0"
                    )
                    last_handshake = 0
            except (ValueError, IndexError):
                self.logger.warning(
                    f"Failed to parse handshake timestamp: {line[:50]}..."
                )
                self.stats["parse_errors"] += 1
                return None

            return PeerInfo(
                iface=iface,
                pubkey=pubkey,
                endpoint=endpoint,
                allowed_ips=allowed_ips,
                last_handshake=last_handshake,
                threshold=self.threshold,
            )

        except (IndexError, ValueError) as e:
            self.logger.warning(f"Parse error: {e}")
            self.stats["parse_errors"] += 1
            return None

    def _format_peer_info(self, peer: PeerInfo) -> str:
        """格式化 Peer 信息用于日志输出（安全版本）"""
        ips = peer.sanitized_allowed_ips
        # 动态标签：如果包含逗号，说明是复数，或者是带掩码的网段（此时保持 IPs 比较安全）
        # 或者我们可以更激进：只有当它是纯IP且没有逗号时，用 IP。
        # 如果 sanitized_allowed_ips 返回的是 "10.0.0.1" (无逗号，无掩码)，用 [IP: ...]
        # 如果是 "10.0.0.1, 10.0.0.2" (有逗号)，用 [IPs: ...]
        # 如果是 "192.168.1.0/24" (fallback情况，带掩码)，用 [IPs: ...] 比较合适，或者 [AllowedIPs: ...]

        # 简单判定：如果没有逗号，且不包含 '/' (说明去掉了掩码)，则为单 IP
        label = "IP" if "," not in ips and "/" not in ips else "IPs"
        return f"[{peer.iface}] {peer.sanitized_pubkey} ({peer.sanitized_endpoint}) [{label}: {ips}]"

    def _format_handshake_time(self, timestamp: int) -> str:
        """格式化握手时间（UTC 时间，避免时区混淆）"""
        if timestamp <= 0:
            return "Never"
        try:
            dt = datetime.datetime.utcfromtimestamp(timestamp)
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except (ValueError, OSError):
            return "Invalid"

    def _print_stats(self) -> None:
        """打印监控统计信息"""
        self.logger.info(
            f"Statistics - Checks: {self.stats['total_checks']}, "
            f"Failures: {self.stats['failed_checks']}, "
            f"State changes: {self.stats['state_changes']}, "
            f"Parse errors: {self.stats['parse_errors']}, "
            f"Tracking peers: {len(self.peer_states)}"
        )

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
            f"Monitor started - Interval: {self.interval}s, "
            f"Threshold: {self.threshold}s, "
            f"Stats interval: {self.stats_interval}s"
        )

        last_stats_time = time.time()

        while self.running:
            loop_start = time.time()
            self.stats["total_checks"] += 1

            # 检查 peer 数量限制
            if not self._check_peer_limit():
                self.running = False
                break

            # 获取 WireGuard 状态
            raw_output = self._fetch_dump()

            if not raw_output:
                self.stats["failed_checks"] += 1
                self._stop_event.wait(timeout=self.interval)
                continue

            # 解析所有 peer
            for line in raw_output.strip().split("\n"):
                if not line.strip():
                    continue

                peer = self._parse_line(line)
                if not peer:
                    continue

                is_online = peer.is_online

                # 新发现的 Peer
                if peer.pubkey not in self.peer_states:
                    self.peer_states[peer.pubkey] = peer
                    log_level = logging.INFO if is_online else logging.WARNING
                    status = "ONLINE" if is_online else "OFFLINE"

                    self.logger.log(
                        log_level,
                        f"New peer discovered: {self._format_peer_info(peer)} - {status} "
                        f"(Last handshake: {self._format_handshake_time(peer.last_handshake)})",
                    )

                else:
                    last_peer = self.peer_states[peer.pubkey]
                    last_is_online = last_peer.is_online

                    # 1. 检测状态翻转
                    if last_is_online != is_online:
                        self.stats["state_changes"] += 1
                        status_str = "ONLINE" if is_online else "OFFLINE"
                        log_level = logging.INFO if is_online else logging.WARNING

                        self.logger.log(
                            log_level,
                            f"Status change: {self._format_peer_info(peer)} → {status_str} "
                            f"(Last handshake: {self._format_handshake_time(peer.last_handshake)})",
                        )

                    # 2. 检测 Endpoint 变更 (Roaming) - 仅在 Online 时或变为 Online 时有意义
                    # 如果之前是 Online 且现在也是 Online，但 Endpoint 变了
                    # 或者如果刚变成 Online，我们已经在上面的 Status change 记录了新的 Endpoint (通过 _format_peer_info)，
                    # 所以这里主要关注 "保持 Online 但换了 IP" 的情况。
                    elif is_online and last_peer.endpoint != peer.endpoint:
                        self.logger.info(
                            f"Endpoint changed (Roaming): {self._format_peer_info(peer)} "
                            f"(Old: {last_peer.sanitized_endpoint} → New: {peer.sanitized_endpoint})"
                        )

                    # 更新状态
                    self.peer_states[peer.pubkey] = peer

            # 定期输出统计
            current_time = time.time()
            if current_time - last_stats_time >= self.stats_interval:
                self._print_stats()
                last_stats_time = current_time

            # 精确的间隔控制
            elapsed = time.time() - loop_start
            sleep_time = max(0, self.interval - elapsed)
            self._stop_event.wait(timeout=sleep_time)

        self.logger.info("Monitor stopped gracefully.")
        self._print_stats()  # 退出前输出最终统计


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
        help=f"Seconds without handshake to consider offline (default: {DEFAULT_OFFLINE_THRESHOLD})",
    )
    parser.add_argument(
        "--stats-interval",
        type=int,
        default=DEFAULT_STATS_INTERVAL,
        help=f"Statistics report interval in seconds (default: {DEFAULT_STATS_INTERVAL})",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--version", action="version", version="WireGuard Monitor v2.0.0"
    )

    return parser.parse_args()


def main() -> None:
    """主入口函数"""
    # 检查权限
    check_root()

    # 解析参数
    args = parse_arguments()

    # 启动监控
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
        # 使用基本配置以确保致命错误被记录（如果没有配置其他 handler）
        if not logging.getLogger().handlers:
            logging.basicConfig(level=logging.ERROR)
        logging.exception(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
