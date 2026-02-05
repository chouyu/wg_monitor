#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root${NC}" 
   exit 1
fi

echo -e "${GREEN}Uninstalling WireGuard Monitor Service...${NC}"

# 停止并禁用服务
echo "Stopping service..."
systemctl stop wg-monitor.service 2>/dev/null || true
systemctl disable wg-monitor.service 2>/dev/null || true

# 删除文件
echo "Removing files..."
rm -f /etc/systemd/system/wg-monitor.service
rm -f /etc/default/wg-monitor
rm -f /etc/logrotate.d/wg-monitor
rm -rf /opt/wg-monitor

# 重载 systemd
echo "Reloading systemd daemon..."
systemctl daemon-reload

echo -e "${GREEN}Uninstallation complete!${NC}"
echo -e "${YELLOW}Log files in /var/log/wg_monitor* were NOT removed.${NC}"
echo "To remove logs: rm -f /var/log/wg_monitor*"
