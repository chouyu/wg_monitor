#!/bin/bash
set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 检查 root 权限
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root${NC}" 
   exit 1
fi

echo -e "${GREEN}Installing WireGuard Monitor Service...${NC}"

# 1. 创建目录
echo "Creating directories..."
mkdir -p /opt/wg-monitor
mkdir -p /var/log

# 2. 复制脚本
echo "Copying monitor script..."
cp wg_monitor.py /opt/wg-monitor/
chmod 755 /opt/wg-monitor/wg_monitor.py

# 3. 检查 Python 依赖
echo "Checking Python version..."
python3 --version || {
    echo -e "${RED}Error: Python 3 is not installed${NC}"
    exit 1
}

# 4. 检查 WireGuard
echo "Checking WireGuard installation..."
which wg > /dev/null || {
    echo -e "${YELLOW}Warning: 'wg' command not found. Please install WireGuard.${NC}"
}

# 5. 安装 systemd 服务
echo "Installing systemd service..."
cp wg-monitor.service /etc/systemd/system/
chmod 644 /etc/systemd/system/wg-monitor.service

# 6. 安装环境配置文件
if [ ! -f /etc/default/wg-monitor ]; then
    echo "Creating default configuration..."
    cat > /etc/default/wg-monitor <<EOF
WG_MONITOR_LOG_PATH="/var/log/wg_monitor.log"
WG_MONITOR_INTERVAL=30
WG_MONITOR_THRESHOLD=180
WG_MONITOR_STATS_INTERVAL=3600
WG_MONITOR_DEBUG=false
PYTHON_BIN=/usr/bin/python3
SCRIPT_PATH=/opt/wg-monitor/wg_monitor.py
EOF
    chmod 644 /etc/default/wg-monitor
else
    echo -e "${YELLOW}Configuration file /etc/default/wg-monitor already exists, skipping...${NC}"
fi

# 7. 安装 logrotate 配置
echo "Installing logrotate configuration..."
cp wg-monitor.logrotate /etc/logrotate.d/wg-monitor
chmod 644 /etc/logrotate.d/wg-monitor

# 8. 重载 systemd
echo "Reloading systemd daemon..."
systemctl daemon-reload

# 9. 启用并启动服务
echo "Enabling service..."
systemctl enable wg-monitor.service

echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "Next steps:"
echo "  1. Edit configuration: nano /etc/default/wg-monitor"
echo "  2. Start service:      systemctl start wg-monitor"
echo "  3. Check status:       systemctl status wg-monitor"
echo "  4. View logs:          journalctl -u wg-monitor -f"
echo "  5. Check log file:     tail -f /var/log/wg_monitor.log"
