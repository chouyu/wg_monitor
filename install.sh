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
if ! command -v wg &> /dev/null; then
    echo -e "${YELLOW}Warning: 'wg' command not found. Please install WireGuard.${NC}"
fi

# 5. 安装 systemd 服务
echo "Installing systemd services..."
cp wg-monitor.service /etc/systemd/system/
cp wg-monitor@.service /etc/systemd/system/
chmod 644 /etc/systemd/system/wg-monitor.service
chmod 644 /etc/systemd/system/wg-monitor@.service

# 6. 安装环境配置文件
echo "Installing default configuration..."
if [ ! -f /etc/default/wg-monitor ]; then
    cp wg-monitor.default /etc/default/wg-monitor
    chmod 644 /etc/default/wg-monitor
else
    echo -e "${YELLOW}Configuration file /etc/default/wg-monitor already exists. Keep existing config.${NC}"
    echo -e "${YELLOW}A new default config is available at wg-monitor.default${NC}"
fi

# 7. 安装 logrotate 配置
echo "Installing logrotate configuration..."
cp wg-monitor.logrotate /etc/logrotate.d/wg-monitor
chmod 644 /etc/logrotate.d/wg-monitor

# 8. 重载 systemd
echo "Reloading systemd daemon..."
systemctl daemon-reload

# 9. 启用并启动服务 (单例模式作为默认)
echo "Enabling default service..."
systemctl enable wg-monitor.service
# 如果服务未运行，则启动；如果已运行，建议用户手动重启
if ! systemctl is-active --quiet wg-monitor.service; then
    echo "Starting service..."
    systemctl start wg-monitor.service
else
    echo -e "${YELLOW}Service is already running. Please restart manually to apply changes: systemctl restart wg-monitor${NC}"
fi

echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "Next steps:"
echo "  1. Edit configuration: nano /etc/default/wg-monitor"
echo "  2. Restart service:    systemctl restart wg-monitor"
echo "  3. Check status:       systemctl status wg-monitor"
echo "  4. Multi-instance:     cp /etc/default/wg-monitor /etc/default/wg-monitor-wg0 && systemctl start wg-monitor@wg0"
