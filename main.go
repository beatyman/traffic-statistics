package main

import (
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

//https://github.com/seal0207/Port-traffic-statistics/blob/main/Port-.sh
//https://github.com/dominikh/simple-router/blob/92e945cdbf054d28b31f3906423ff08265ca4837/traffic/statistics.go

type ReportNetStatistics struct {
	HostId           string     `json:"host_id"`
	PortTraffic      []*Stat    `json:"port_traffic"`
	InterfaceTraffic []VNResult `json:"interface_traffic"`
	Version          string     `json:"version"`
	TimeStamp        int64      `json:"time_stamp"`
}

func main() {
	tool := PortTrafficStatistics{}
	ports, _ := tool.readStatistics()
	cmd := exec.Command("vnstat", "--help")
	err := cmd.Run()
	if err != nil {
		log.Infof("%+v", err)
	}
	data := VN("enp8s0")
	report := ReportNetStatistics{
		HostId:      "dfd92628e5ff68080335265edf804aea4e6e8df5112464",
		PortTraffic: ports,
		InterfaceTraffic: []VNResult{
			data,
		},
		Version: "0.0.0",
		TimeStamp: time.Now().Unix(),
	}
	bytesNet, _ := json.Marshal(report)
	log.Infof("%+v", string(bytesNet))
	/*	if err := tool.addPort([]string{"2348", "8086"}); err != nil {
			log.Error(err)
			return
		}
		if err := tool.deletePort([]string{"2348"}); err != nil {
			log.Error(err)
			return
		}
		if err := tool.clearAll(); err != nil {
			log.Error(err)
			return
		}*/
}

// Stat represents a structured statistic entry.
type Stat struct {
	Packets  uint64 `json:"packets"`
	Bytes    uint64 `json:"bytes"`
	Protocol string `json:"protocol"`
	Port     string `json:"port"`
}

type PortTrafficStatistics struct {
}

func (p *PortTrafficStatistics) addPort(ports []string) error {
	log.Infof("添加端口流量统计规则：%+v ", ports)
	for _, port := range ports {
		//iptables -I INPUT -p tcp --dport $ports
		_, err := exec.Command("iptables", "-I", "INPUT", "-p", "tcp", "--dport", port).Output()
		if err != nil {
			log.Error(err)
			return err
		}
		log.Infof("success: iptables -I INPUT -p tcp --dport %+v ", port)
		//iptables -I INPUT -p udp --dport $ports
		_, err = exec.Command("iptables", "-I", "INPUT", "-p", "udp", "--dport", port).Output()
		if err != nil {
			log.Error(err)
			return err
		}
		log.Infof("success: iptables -I INPUT -p udp --dport %+v ", port)
		//iptables -I OUTPUT -p tcp --sport $ports
		_, err = exec.Command("iptables", "-I", "OUTPUT", "-p", "tcp", "--sport", port).Output()
		if err != nil {
			log.Error(err)
			return err
		}
		log.Infof("success: iptables -I OUTPUT -p tcp --sport %+v ", port)
		//iptables -I OUTPUT -p udp --sport $ports
		_, err = exec.Command("iptables", "-I", "OUTPUT", "-p", "udp", "--sport", port).Output()
		if err != nil {
			log.Error(err)
			return err
		}
		log.Infof("success: iptables -I OUTPUT -p udp --sport  %+v ", port)
	}
	return nil
}

func (p *PortTrafficStatistics) deletePort(ports []string) error {
	log.Infof("删除流量统计规则: %+v ", ports)
	for _, port := range ports {
		//iptables -D INPUT -p tcp --dport $ports
		_, err := exec.Command("iptables", "-D", "INPUT", "-p", "tcp", "--dport", port).Output()
		if err != nil {
			log.Error(err)
			return err
		}
		log.Infof("success: iptables -D INPUT -p tcp --dport  %+v ", port)
		//iptables -D INPUT -p udp --dport $ports
		_, err = exec.Command("iptables", "-D", "INPUT", "-p", "udp", "--dport", port).Output()
		if err != nil {
			log.Error(err)
			return err
		}
		log.Infof("success: iptables -D INPUT -p udp --dport  %+v ", port)
		//iptables -D OUTPUT -p tcp --sport $ports
		_, err = exec.Command("iptables", "-D", "OUTPUT", "-p", "tcp", "--sport", port).Output()
		if err != nil {
			log.Error(err)
			return err
		}
		log.Infof("success: iptables -D OUTPUT -p tcp --sport  %+v ", port)
		//iptables -D OUTPUT -p udp --sport $ports
		_, err = exec.Command("iptables", "-D", "OUTPUT", "-p", "udp", "--sport", port).Output()
		if err != nil {
			log.Error(err)
			return err
		}
		log.Infof("success: iptables -D OUTPUT -p udp --sport  %+v ", port)
	}
	return nil
}

//iptables 计数清空
func (p *PortTrafficStatistics) reCount() error {
	log.Info("重置流量统计计数")
	_, err := exec.Command("iptables", "-Z").Output()
	if err != nil {
		log.Error(err)
		return err
	}
	return nil
}

//清除所有规则
func (p *PortTrafficStatistics) clearAll() error {
	log.Info("清理所有iptables规则")
	_, err := exec.Command("iptables", "-F").Output()
	if err != nil {
		log.Error(err)
		return err
	}
	return nil
}

func (p *PortTrafficStatistics) readStatistics() ([]*Stat, error) {
	log.Infof("解析流量数据")
	data, err := p.chainList("filter", "INPUT")
	if err != nil {
		log.Error(err)
		return nil, err
	}
	stats, err := p.ParseStat(data)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	for _, stst := range stats {
		log.Infof("%+v", stst)
	}
	return stats, nil
}

func (p *PortTrafficStatistics) chainList(table, chain string) (string, error) {
	iptablePath, err := exec.LookPath("iptables")
	if err != nil {
		return "", err
	}
	var args []string
	name := iptablePath
	args = append(args, "-w", "5")
	args = append(args, "-nvL", chain, "-t", table, "-x")
	c := exec.Command(name, args...)
	out, err := c.Output()
	return string(out), err
}

var chainNameRe = regexp.MustCompile(`^Chain\s+(\S+)`)
var fieldsHeaderRe = regexp.MustCompile(`^\s*pkts\s+bytes\s+`)

// pkts      bytes target     prot opt in     out     source               destination
func (p *PortTrafficStatistics) ParseStat(data string) ([]*Stat, error) {
	stats := make([]*Stat, 0)
	lines := strings.Split(data, "\n")
	if len(lines) < 3 {
		return nil, fmt.Errorf("annot parse iptables list information %+v", lines)
	}
	mchain := chainNameRe.FindStringSubmatch(lines[0])
	if mchain == nil {
		return nil, fmt.Errorf("annot parse iptables list information %+v", lines)
	}
	if !fieldsHeaderRe.MatchString(lines[1]) {
		return nil, fmt.Errorf("annot parse iptables list information %+v", lines)
	}
	var err error
	for _, line := range lines[2:] {
		stat := strings.Fields(line)
		if len(stat) < 10 {
			log.Errorf("annot parse iptables list information %+v", stat)
			continue
		}
		lStat := new(Stat)
		// Convert the fields that are not plain strings
		lStat.Packets, err = strconv.ParseUint(stat[0], 0, 64)
		if err != nil {
			log.Errorf("annot parse iptables list information %+v", stat)
			continue
		}
		lStat.Bytes, err = strconv.ParseUint(stat[1], 0, 64)
		if err != nil {
			log.Errorf("annot parse iptables list information %+v", stat)
			continue
		}
		lStat.Protocol = stat[2]
		dports := strings.Split(stat[9], ":")
		if len(dports) != 2 {
			log.Errorf("annot parse iptables list information %+v", stat)
			continue
		}
		lStat.Port = dports[1]
		stats = append(stats, lStat)
	}
	return stats, nil
}
