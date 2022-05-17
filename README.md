# traffic-statistics

## 流量统计
### iptables 统计端口流量
 1. 出口流量: iptables -n -v -t filter -L OUTPUT
 2. 入口流量：iptables -n -v -t filter -L INPUT

### vnstat 统计月，天，小时累计流量
 1. 月流量 vnstat -m -i enp8s0
 2. 天流量 vnstat -d -i enp8s0
 3. 小时流量 vnstat -h -i enp8s0
