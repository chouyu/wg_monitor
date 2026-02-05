# 1. 下载或克隆仓库
cd /tmp
# 假设文件已准备好

# 2. 赋予执行权限
chmod +x install.sh uninstall.sh

# 3. 运行安装脚本
sudo ./install.sh

# 4. 启动服务
sudo systemctl start wg-monitor

# 5. 检查状态
sudo systemctl status wg-monitor

# 启动服务
sudo systemctl start wg-monitor

# 停止服务
sudo systemctl stop wg-monitor

# 重启服务
sudo systemctl restart wg-monitor

# 查看状态
sudo systemctl status wg-monitor

# 查看实时日志（journald）
sudo journalctl -u wg-monitor -f

# 查看最近 100 行日志
sudo journalctl -u wg-monitor -n 100

# 查看文件日志
sudo tail -f /var/log/wg_monitor.log

# 查看启动失败原因
sudo journalctl -u wg-monitor -xe

# 重新加载配置（修改 /etc/default/wg-monitor 后）
sudo systemctl restart wg-monitor

# 查看服务性能统计
sudo systemctl show wg-monitor --property=MemoryCurrent,CPUUsageNSec

# 编辑环境配置
sudo nano /etc/default/wg-monitor

# 编辑服务文件（需重载）
sudo nano /etc/systemd/system/wg-monitor.service
sudo systemctl daemon-reload
sudo systemctl restart wg-monitor

# 1. 检查服务状态
sudo systemctl status wg-monitor

# 2. 查看详细错误
sudo journalctl -u wg-monitor --since "10 minutes ago"

# 3. 手动运行测试
sudo /usr/bin/python3 /opt/wg-monitor/wg_monitor.py --debug

# 4. 检查权限
ls -la /opt/wg-monitor/
ls -la /var/log/wg_monitor.log

# 5. 检查 WireGuard
sudo wg show all dump
# 为 wg0 创建配置
sudo nano /etc/default/wg-monitor-wg0

# 启动多个实例
sudo systemctl start wg-monitor@wg0
sudo systemctl start wg-monitor@wg1
