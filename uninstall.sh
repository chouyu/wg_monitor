#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root${NC}" 
   echo -e "${RED}错误：必须以 root 权限运行此脚本${NC}"
   exit 1
fi

echo -e "${GREEN}Uninstalling WireGuard Monitor...${NC}"
echo -e "${GREEN}正在卸载 WireGuard 监控器...${NC}"

# 停止服务
echo "Stopping services..."
echo "正在停止服务..."
systemctl stop wg-monitor.service || true
# 尝试停止所有模板实例
for service in $(systemctl list-units --full --all | grep -o 'wg-monitor@.*\.service'); do
    echo "Stopping $service..."
    echo "正在停止 $service..."
    systemctl stop "$service" || true
    systemctl disable "$service" || true
done
systemctl disable wg-monitor.service || true

# 删除文件
echo "Removing files..."
echo "正在删除文件..."
rm -f /etc/systemd/system/wg-monitor.service
rm -f /etc/systemd/system/wg-monitor@.service
rm -f /etc/logrotate.d/wg-monitor
rm -rf /opt/wg-monitor

# 备份配置文件而不是直接删除
if [ -f /etc/default/wg-monitor ]; then
    echo "Backing up configuration to /etc/default/wg-monitor.bak"
    echo "正在备份配置到 /etc/default/wg-monitor.bak"
    mv /etc/default/wg-monitor /etc/default/wg-monitor.bak
fi
# 备份实例配置
for config in /etc/default/wg-monitor-*; do
    if [ -f "$config" ]; then
         echo "Backing up instance config $config to ${config}.bak"
         echo "正在备份实例配置 $config 到 ${config}.bak"
         mv "$config" "${config}.bak"
    fi
done

# 重载 systemd
systemctl daemon-reload

echo -e "${GREEN}Uninstallation complete.${NC}"
echo -e "${GREEN}卸载完成。${NC}"
echo "Logs in /var/log/wg_monitor.log were preserved."
echo "位于 /var/log/wg_monitor.log 的日志已保留。"
