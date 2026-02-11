# WireGuard Peer Status Monitor & Logger
# WireGuard 节点状态监控与审计记录器

A production-grade auditing tool for WireGuard VPNs. It continuously monitors peer connectivity and maintains a **precise historical log of connection events** (Online/Offline transitions) based on handshake timestamps.

这是一个用于 WireGuard VPN 的生产级审计工具。它持续监控 Peer 的连通性，并基于握手时间戳维护**精确的连接事件历史日志**（上线/下线记录）。

## Why use this?
## 为什么使用本工具？

While `wg show` gives you the *current* status, it doesn't tell you **when** a peer connected or disconnected. This tool fills that gap by providing a persistent audit trail, essential for:

虽然 `wg show` 命令能提供*当前*状态，但它无法告诉你 Peer 是**何时**连接或断开的。本工具通过提供持久的审计追踪来填补这一空白，这对于以下场景至关重要：

- **Security Auditing**: Know exactly when users access the VPN.
- **安全审计**：准确知晓用户何时访问了 VPN。
- **Troubleshooting**: Correlate connectivity issues with specific timestamps.
- **故障排查**：将连接问题与具体时间点关联起来。
- **Usage Analysis**: Track session durations and stability.
- **使用分析**：追踪会话时长和稳定性。

## Key Features
## 核心特性

- **Connection Auditing**: Logs `ONLINE` and `OFFLINE` events with precise local timestamps.
- **连接审计**：记录 `ONLINE`（上线）和 `OFFLINE`（下线）事件及精确的本地时间戳。

- **Zero Dependencies**: Written in pure Python 3 (Standard Library only). No `pip install` required.
- **零依赖**：纯 Python 3 编写（仅使用标准库）。无需 `pip install`。

- **Production Ready**: Runs as a Systemd service with logrotate-based log rotation (1MB x 7 rotations).
- **生产就绪**：作为 Systemd 服务运行，通过 logrotate 进行日志轮转（1MB x 7 个轮转）。

- **Security First**: 
- **安全优先**：
  - Strict input validation and sanitization.
  - 严格的输入验证和清洗。
  - Path traversal protection.
  - 路径遍历防护。
  - Safe subprocess execution with environment isolation.
  - 带有环境隔离的安全子进程执行。

- **Configurable**: Customizable check intervals and timeout thresholds.
- **可配置**：支持自定义检查间隔和超时阈值。

## Audit Log Example
## 审计日志示例

The tool generates structured logs in `/var/log/wg_monitor.log`:

工具会在 `/var/log/wg_monitor.log` 生成结构化日志：

```text
2023-10-27 10:00:00 Monitor started | Interval: 30s, Threshold: 180s, Stats: 3600s
2023-10-27 10:01:30 ONLINE  [wg0] AbC1dEf2...4xYz5678 (192.168.1.50:51820) [IP: 10.0.0.1] new (handshake: 10:01:25)
2023-10-27 10:45:00 OFFLINE [wg0] AbC1dEf2...4xYz5678 (192.168.1.50:51820) [IP: 10.0.0.1] (handshake: 10:01:25)
2023-10-27 11:15:20 ONLINE  [wg0] AbC1dEf2...4xYz5678 (192.168.1.50:51820) [IP: 10.0.0.1] (handshake: 11:15:15)
```

## Requirements
## 环境要求

- Linux system (Requires Root privileges to run `wg show`)
- Linux 系统（需要 Root 权限以运行 `wg show`）
- Python 3.7+
- WireGuard installed (`wg` command available)
- 已安装 WireGuard（需要 `wg` 命令）

## Installation
## 安装

### Automatic Installation
### 自动安装

The included script installs the monitor as a systemd service:

包含的脚本会将监控器安装为 systemd 服务：

```bash
# 1. Clone repository / 克隆仓库
git clone https://github.com/chouyu/wg_monitor.git
cd wg_monitor

# 2. Run installer (requires sudo) / 运行安装程序（需要 sudo）
sudo ./install.sh
```

### Manual Installation
### 手动安装

If you prefer manual setup:

如果您更喜欢手动设置：

1.  Copy `wg_monitor.py` to `/opt/wg-monitor/`.
1.  将 `wg_monitor.py` 复制到 `/opt/wg-monitor/`。

2.  Copy `wg-monitor.default` to `/etc/default/wg-monitor`.
2.  将 `wg-monitor.default` 复制到 `/etc/default/wg-monitor`。

3.  Copy `wg-monitor.service` to `/etc/systemd/system/`.
3.  将 `wg-monitor.service` 复制到 `/etc/systemd/system/`。

4.  Reload systemd and start:
4.  重载 systemd 并启动：
    ```bash
    sudo systemctl daemon-reload
    sudo systemctl enable --now wg-monitor
    ```

## Configuration
## 配置

You can configure the service by editing `/etc/default/wg-monitor`.

您可以通过编辑 `/etc/default/wg-monitor` 来配置服务。

| Variable / 变量 | Flag / 参数 | Default / 默认 | Description / 说明 |
|-----------------|-------------|----------------|-------------------|
| `LOG_PATH` | `--log-path` | `/var/log/wg_monitor.log` | Path to the log file.<br>日志文件路径。 |
| `INTERVAL` | `--interval` | `30` | How often (seconds) to check peer status.<br>检查 Peer 状态的频率（秒）。 |
| `THRESHOLD`| `--threshold`| `180` | Seconds since last handshake to mark peer offline.<br>标记 Peer 为离线的无握手时长（秒）。 |
| `STATS_INTERVAL` | `--stats-interval`| `3600` | How often (seconds) to output summary statistics to console.<br>输出统计摘要到控制台的频率（秒）。 |
| `DEBUG` | `--debug` | `false` | Enable verbose debug logging.<br>启用详细调试日志。 |

### Running Multiple Instances
### 运行多个实例

The service supports multiple instances (e.g., for different interfaces or configurations).
Use the `@` syntax with a configuration file suffix:

服务支持多实例（例如用于不同的接口或配置）。
使用 `@` 语法配合配置文件后缀：

1.  Create config: `/etc/default/wg-monitor-wg0`
1.  创建配置：`/etc/default/wg-monitor-wg0`
2.  Start service: `sudo systemctl start wg-monitor@wg0`
2.  启动服务：`sudo systemctl start wg-monitor@wg0`

## Usage
## 使用

### Check Service Status / 检查服务状态
```bash
sudo systemctl status wg-monitor
```

### View Logs / 查看日志

Real-time logs from journald:
查看 journald 实时日志：
```bash
sudo journalctl -u wg-monitor -f
```

File logs (connection history):
查看文件日志（连接历史）：
```bash
sudo tail -f /var/log/wg_monitor.log
```

### Manual Debug Run / 手动调试运行
```bash
sudo python3 wg_monitor.py --debug --interval 5 --threshold 60
```

## Development
## 开发

### Running Tests
### 运行测试

This project uses `pytest` for testing. Since it has no external dependencies for production, you only need dev tools for testing.

本项目使用 `pytest` 进行测试。由于生产环境无外部依赖，您只需安装开发工具即可进行测试。

```bash
# Install dev dependencies / 安装开发依赖
pip install pytest mypy ruff

# Run unit tests / 运行单元测试
pytest

# Run type checks / 运行类型检查
mypy wg_monitor.py tests/

# Run linter / 运行代码风格检查
ruff check .
```

## Security Design
## 安全设计

Since this tool runs as root (required for `wg`), security is paramount:

由于本工具以 root 运行（`wg` 需要），安全性至关重要：

1.  **Environment Isolation**: When invoking `wg`, the environment is copied but `PATH` is restricted to `/usr/bin:/usr/sbin:/bin:/sbin`.
1.  **环境隔离**：调用 `wg` 时，会复制环境变量，但 `PATH` 被限制为 `/usr/bin:/usr/sbin:/bin:/sbin`。

2.  **Input Sanitization**: All data from `wg show` (pubkeys, endpoints) is sanitized before logging to prevent log injection attacks.
2.  **输入清洗**：来自 `wg show` 的所有数据（公钥、端点）在记录前都会经过清洗，以防止日志注入攻击。

3.  **Path Validation**: Log paths are strictly validated against a whitelist (`/var/log`, `/tmp`, `./logs`) to prevent arbitrary file overwrites.
3.  **路径验证**：日志路径严格遵循白名单（`/var/log`, `/tmp`, `./logs`），以防止任意文件覆盖。

## License
## 许可证

[MIT License](LICENSE)
