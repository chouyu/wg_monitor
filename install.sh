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
   echo -e "${RED}错误：必须以 root 权限运行此脚本${NC}"
   exit 1
fi

echo -e "${GREEN}Installing WireGuard Monitor Service...${NC}"
echo -e "${GREEN}正在安装 WireGuard 监控服务...${NC}"

# 1. 创建目录
echo "Creating directories..."
echo "正在创建目录..."
mkdir -p /opt/wg-monitor
mkdir -p /var/log

# 2. 复制脚本
echo "Copying monitor script..."
echo "正在复制监控脚本..."
cp wg_monitor.py /opt/wg-monitor/
chmod 755 /opt/wg-monitor/wg_monitor.py

# 3. 检查 Python 依赖
echo "Checking Python version..."
echo "正在检查 Python 版本..."
python3 --version || {
    echo -e "${RED}Error: Python 3 is not installed${NC}"
    echo -e "${RED}错误：未安装 Python 3${NC}"
    exit 1
}

# 4. 检查 WireGuard
echo "Checking WireGuard installation..."
echo "正在检查 WireGuard 安装..."
if ! command -v wg &> /dev/null; then
    echo -e "${YELLOW}Warning: 'wg' command not found. Please install WireGuard.${NC}"
    echo -e "${YELLOW}警告：未找到 'wg' 命令。请安装 WireGuard。${NC}"
fi

# 5. 安装 systemd 服务
echo "Installing systemd services..."
echo "正在安装 systemd 服务..."
cp wg-monitor.service /etc/systemd/system/
cp wg-monitor@.service /etc/systemd/system/
chmod 644 /etc/systemd/system/wg-monitor.service
chmod 644 /etc/systemd/system/wg-monitor@.service

# 6. 安装环境配置文件
echo "Installing default configuration..."
echo "正在安装默认配置..."
if [ ! -f /etc/default/wg-monitor ]; then
    cp wg-monitor.default /etc/default/wg-monitor
    chmod 644 /etc/default/wg-monitor
else
    echo -e "${YELLOW}Configuration file /etc/default/wg-monitor already exists. Keep existing config.${NC}"
    echo -e "${YELLOW}配置文件 /etc/default/wg-monitor 已存在。保留现有配置。${NC}"
    echo -e "${YELLOW}A new default config is available at wg-monitor.default${NC}"
    echo -e "${YELLOW}新的默认配置已保存为 wg-monitor.default${NC}"
fi

# 7. 安装 logrotate 配置
echo "Installing logrotate configuration..."
echo "正在安装 logrotate 配置..."
cp wg-monitor.logrotate /etc/logrotate.d/wg-monitor
chmod 644 /etc/logrotate.d/wg-monitor

# 8. 重载 systemd
echo "Reloading systemd daemon..."
echo "正在重载 systemd 守护进程..."
systemctl daemon-reload

# 9. 启用并启动服务 (单例模式作为默认)
echo "Enabling default service..."
echo "正在启用默认服务..."
systemctl enable wg-monitor.service

# 如果服务未运行，则启动；如果已运行，建议用户手动重启
if ! systemctl is-active --quiet wg-monitor.service; then
    echo "Starting service..."
    echo "正在启动服务..."
    systemctl start wg-monitor.service
else
    echo -e "${YELLOW}Service is already running. Please restart manually to apply changes: systemctl restart wg-monitor${NC}"
    echo -e "${YELLOW}服务已在运行。请手动重启以应用更改：systemctl restart wg-monitor${NC}"
fi

echo -e "${GREEN}Installation complete!${NC}"
echo -e "${GREEN}安装完成！${NC}"
echo ""
echo "Next steps / 下一步:"
echo "  1. Edit configuration: nano /etc/default/wg-monitor"
echo "     编辑配置："
echo "  2. Restart service:    systemctl restart wg-monitor"
echo "     重启服务："
echo "  3. Check status:       systemctl status wg-monitor"
echo "     检查状态："
echo "  4. Multi-instance:     cp /etc/default/wg-monitor /etc/default/wg-monitor-wg0 && systemctl start wg-monitor@wg0"
echo "     多实例运行："
