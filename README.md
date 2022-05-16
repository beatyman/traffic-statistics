# traffic-statistics

//流量统计
// iptables 统计端口流量
// 出口流量: iptables -n -v -t filter -L OUTPUT
// 入口流量：iptables -n -v -t filter -L INPUT

//vnstat 统计月，天，小时累计流量
//月流量 vnstat -m -i enp8s0
//天流量 vnstat -d -i enp8s0
//小时流量 vnstat -h -i enp8s0
