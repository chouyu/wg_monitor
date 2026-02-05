# Agent Guidelines for wg_monitor

This repository contains a WireGuard Peer Status Monitor tool written in Python. It is a production-grade utility designed to run as a systemd service.

## 1. Project Overview
- **Language**: Python 3.7+
- **Key File**: `wg_monitor.py` (Single-file architecture)
- **Dependencies**: Standard library only (no `pip install` required). Depends on system `wg` command.
- **Platform**: Linux (requires Root privileges for `wg` and systemd interactions)

## 2. Build & Run
- **No Build Step**: Pure Python script.
- **Run Manually (Debug)**:
  ```bash
  sudo python3 wg_monitor.py --debug --interval 5 --threshold 60
  ```
- **Run as Service**:
  ```bash
  sudo systemctl start wg-monitor
  ```
- **Installation**:
  ```bash
  sudo ./install.sh
  ```

## 3. Testing
- **Automated Tests**: None currently implemented.
- **Manual Verification**:
  1. Run with `--debug` flag.
  2. Verify output against `sudo wg show` state.
  3. Check logs at `/var/log/wg_monitor.log` (or configured path).

## 4. Code Style & Conventions
- **Formatting**: Follow PEP 8.
- **Type Hints**: **MANDATORY** for all function arguments and return values.
  - Use `typing` module (`Dict`, `List`, `Optional`, etc.) or standard types.
- **Docstrings**: Required for all classes and functions. Describe purpose, args, and returns.
- **Naming**:
  - Classes: `CamelCase`
  - Functions/Variables: `snake_case`
  - Constants: `UPPER_CASE`
- **Imports**: Group standard library imports first, then third-party (none currently), then local.

## 5. Security Guidelines (CRITICAL)
- **Input Validation**: Sanitize all external inputs (e.g., from `wg` command output).
- **Path Safety**: Use `pathlib` and validate paths to prevent traversal attacks.
- **Log Injection**: Sanitize data before logging (remove newlines/control characters).
- **Privilege**: Script runs as root, so be extremely careful with `subprocess` calls. Always use absolute paths or restricted environment.

## 6. Architecture Patterns
- **Dataclasses**: Use `@dataclass` for data structures (e.g., `PeerInfo`).
- **Error Handling**:
  - Catch specific exceptions (`subprocess.CalledProcessError`, `OSError`).
  - Never use bare `except:`.
  - Log errors with context.
- **Concurrency**: Simple threading `Event` used for graceful shutdown.

## 7. Cursor/Copilot Rules
- **Preference**: Concise, type-safe Python code.
- **Avoid**: Adding heavy third-party dependencies unless necessary. Keep it lightweight.
