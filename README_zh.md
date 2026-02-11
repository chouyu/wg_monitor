[English](README.md)

# WireGuard 节点状态监控与审计记录器

这是一个用于 WireGuard VPN 的生产级审计工具。它持续监控 Peer 的连通性，并基于握手时间戳维护**精确的连接事件历史日志**（上线/下线记录）。

## 为什么使用本工具？

虽然 `wg show` 命令能提供*当前*状态，但它无法告诉你 Peer 是**何时**连接或断开的。本工具通过提供持久的审计追踪来填补这一空白，这对于以下场景至关重要：

- **安全审计**：准确知晓用户何时访问了 VPN。
- **故障排查**：将连接问题与具体时间点关联起来。
- **使用分析**：追踪会话时长和稳定性。

## 核心特性

- **连接审计**：记录 `ONLINE`（上线）和 `OFFLINE`（下线）事件及精确的本地时间戳。

- **零依赖**：纯 Python 3 编写（仅使用标准库）。无需 `pip install`。

- **生产就绪**：作为 Systemd 服务运行，通过 logrotate 进行日志轮转（1MB x 7 个轮转）。

- **安全优先**：
  - 严格的输入验证和清洗。
  - 路径遍历防护。
  - 带有环境隔离的安全子进程执行。

- **可配置**：支持自定义检查间隔和超时阈值。

- **状态变更脚本**：当 Peer 状态发生变化时，可执行自定义脚本，并通过环境变量传递完整的 Peer 信息。

## 审计日志示例

工具会在 `/var/log/wg_monitor.log` 生成结构化日志：

```text
2023-10-27 10:00:00 Monitor started | Interval: 30s, Threshold: 180s, Stats: 3600s
2023-10-27 10:01:30 ONLINE  [wg0] AbC1dEf2...4xYz5678 (192.168.1.50:51820) [IP: 10.0.0.1] new (handshake: 10:01:25)
2023-10-27 10:45:00 OFFLINE [wg0] AbC1dEf2...4xYz5678 (192.168.1.50:51820) [IP: 10.0.0.1] (handshake: 10:01:25)
2023-10-27 11:15:20 ONLINE  [wg0] AbC1dEf2...4xYz5678 (192.168.1.50:51820) [IP: 10.0.0.1] (handshake: 11:15:15)
```

## 环境要求

- Linux 系统（需要 Root 权限以运行 `wg show`）
- Python 3.7+
- 已安装 WireGuard（需要 `wg` 命令）

## 安装

### 自动安装

包含的脚本会将监控器安装为 systemd 服务：

```bash
# 1. 克隆仓库
git clone https://github.com/chouyu/wg_monitor.git
cd wg_monitor

# 2. 运行安装程序（需要 sudo）
sudo ./install.sh
```

### 手动安装

如果您更喜欢手动设置：

1.  将 `wg_monitor.py` 复制到 `/opt/wg-monitor/`。
2.  将 `wg-monitor.default` 复制到 `/etc/default/wg-monitor`。
3.  将 `wg-monitor.service` 复制到 `/etc/systemd/system/`。
4.  重载 systemd 并启动：
    ```bash
    sudo systemctl daemon-reload
    sudo systemctl enable --now wg-monitor
    ```

## 配置

您可以通过编辑 `/etc/default/wg-monitor` 来配置服务。

| 变量 | 参数 | 默认值 | 说明 |
|------|------|--------|------|
| `LOG_PATH` | `--log-path` | `/var/log/wg_monitor.log` | 日志文件路径。 |
| `INTERVAL` | `--interval` | `30` | 检查 Peer 状态的频率（秒）。 |
| `THRESHOLD` | `--threshold` | `180` | 标记 Peer 为离线的无握手时长（秒）。 |
| `STATS_INTERVAL` | `--stats-interval` | `3600` | 输出统计摘要到控制台的频率（秒）。 |
| `INTERFACE` | `--interface` | *（全部）* | 仅监控指定的 WireGuard 接口（如 `wg0`）。未设置时监控所有接口。 |
| `ON_CHANGE_SCRIPT` | `--on-change-script` | *（无）* | Peer 状态变更时执行的脚本路径。 |
| `DEBUG` | `--debug` | `false` | 启用详细调试日志。 |

### 状态变更脚本

设置 `--on-change-script` 后，每当 Peer 在上线和下线状态之间切换时，都会执行指定的脚本。以下环境变量会传递给脚本：

| 变量 | 说明 |
|------|------|
| `PEER_EVENT` | 事件类型：`ONLINE`、`OFFLINE` 或 `REMOVED`。 |
| `PEER_IFACE` | WireGuard 接口名称（如 `wg0`）。 |
| `PEER_PUBKEY` | Peer 的公钥。 |
| `PEER_ENDPOINT` | Peer 的端点地址（如 `192.168.1.50:51820`）。 |
| `PEER_ALLOWED_IPS` | Peer 的允许 IP。 |
| `PEER_HANDSHAKE` | Peer 上次握手的时间戳。 |
| `PEER_ONLINE` | Peer 当前在线为 `1`，离线为 `0`。 |

示例脚本：

```bash
#!/bin/bash
echo "$(date) $PEER_EVENT on $PEER_IFACE: $PEER_PUBKEY from $PEER_ENDPOINT" >> /var/log/wg_changes.log
```

### 运行多个实例

服务支持多实例（例如用于不同的接口或配置）。
使用 `@` 语法配合配置文件后缀：

1.  创建配置：`/etc/default/wg-monitor-wg0`
2.  启动服务：`sudo systemctl start wg-monitor@wg0`

## 使用

### 检查服务状态
```bash
sudo systemctl status wg-monitor
```

### 查看日志

查看 journald 实时日志：
```bash
sudo journalctl -u wg-monitor -f
```

查看文件日志（连接历史）：
```bash
sudo tail -f /var/log/wg_monitor.log
```

### 手动调试运行
```bash
sudo python3 wg_monitor.py --debug --interval 5 --threshold 60
```

## 开发

### 运行测试

本项目使用 `pytest` 进行测试。由于生产环境无外部依赖，您只需安装开发工具即可进行测试。

```bash
# 安装开发依赖
pip install pytest mypy ruff

# 运行单元测试
pytest

# 运行类型检查
mypy wg_monitor.py tests/

# 运行代码风格检查
ruff check .
```

## 安全设计

由于本工具以 root 运行（`wg` 需要），安全性至关重要：

1.  **命令解析**：启动时在 `/usr/bin:/usr/sbin:/bin:/sbin` 范围内将 `wg` 解析为绝对路径，后续所有调用复用该路径。

2.  **输入清洗**：来自 `wg show` 的所有数据（公钥、端点）在记录前都会经过清洗，以防止日志注入攻击。

3.  **路径验证**：日志路径严格遵循白名单（`/var/log`、`/tmp`），以防止任意文件覆盖。

## 许可证

[MIT License](LICENSE)
