# WireGuard Peer Status Monitor

A production-grade, lightweight monitoring tool designed to track WireGuard peer connectivity status. It analyzes handshake timestamps to detect peer online/offline states and logs transitions, enabling reliable monitoring for WireGuard VPN infrastructure.

## Key Features

- **Zero Dependencies**: Written in pure Python 3 (Standard Library only). No `pip install` required.
- **Production Ready**: Designed to run as a Systemd service with graceful shutdown handling.
- **Security First**: 
  - Strict input validation and sanitization.
  - Path traversal protection for log files.
  - Safe subprocess execution with environment isolation.
- **Robust Logging**: Built-in log rotation (10MB x 5 backups) and standardized format.
- **Configurable**: Customizable check intervals, offline thresholds, and log paths.

## Requirements

- Linux system (Requires Root privileges to run `wg show`)
- Python 3.7+
- WireGuard installed (`wg` command available)

## Installation

### Automatic Installation

The included script installs the monitor as a systemd service:

```bash
# 1. Clone repository
git clone https://github.com/your-repo/wg_monitor.git
cd wg_monitor

# 2. Run installer (requires sudo)
sudo ./install.sh
```

### Manual Installation

If you prefer manual setup:

1.  Copy `wg_monitor.py` to `/opt/wg-monitor/`.
2.  Copy `wg-monitor.default` to `/etc/default/wg-monitor`.
3.  Copy `wg-monitor.service` to `/etc/systemd/system/`.
4.  Reload systemd and start:
    ```bash
    sudo systemctl daemon-reload
    sudo systemctl enable --now wg-monitor
    ```

## Configuration

You can configure the service by editing `/etc/default/wg-monitor`.

| Variable | Flag | Default | Description |
|----------|------|---------|-------------|
| `LOG_PATH` | `--log-path` | `/var/log/wg_monitor.log` | Path to the log file. |
| `CHECK_INTERVAL` | `--interval` | `30` | How often (seconds) to check peer status. |
| `OFFLINE_THRESHOLD`| `--threshold`| `180` | Seconds since last handshake to mark peer offline. |
| `STATS_INTERVAL` | `--stats-interval`| `3600` | How often (seconds) to log summary statistics. |
| `DEBUG` | `--debug` | (Disabled) | Enable verbose debug logging. |

### Running Multiple Instances

The service supports multiple instances (e.g., for different interfaces or configurations).
Use the `@` syntax with a configuration file suffix:

1.  Create config: `/etc/default/wg-monitor-wg0`
2.  Start service: `sudo systemctl start wg-monitor@wg0`

## Usage

### Check Service Status
```bash
sudo systemctl status wg-monitor
```

### View Logs
Real-time logs from journald:
```bash
sudo journalctl -u wg-monitor -f
```

File logs (if configured):
```bash
sudo tail -f /var/log/wg_monitor.log
```

### Manual Debug Run
```bash
sudo python3 wg_monitor.py --debug --interval 5 --threshold 60
```

## Development

### Running Tests
This project uses `pytest` for testing. Since it has no external dependencies for production, you only need dev tools for testing.

```bash
# Install dev dependencies
pip install pytest mypy ruff

# Run unit tests
pytest

# Run type checks
mypy wg_monitor.py tests/

# Run linter
ruff check .
```

## Security Design

Since this tool runs as root (required for `wg`), security is paramount:
1.  **Environment Isolation**: When invoking `wg`, the environment is copied but `PATH` is restricted to `/usr/bin:/usr/sbin:/bin:/sbin`.
2.  **Input Sanitization**: All data from `wg show` (pubkeys, endpoints) is sanitized before logging to prevent log injection attacks.
3.  **Path Validation**: Log paths are strictly validated against a whitelist (`/var/log`, `/tmp`, `./logs`) to prevent arbitrary file overwrites.

## License

[MIT License](LICENSE)
