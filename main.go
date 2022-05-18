package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
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

func Startup(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	log.Info("health daemon startup")
	getAgentStat(time.Now())
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-ticker.C:
			{
				getAgentStat(t)
			}
		}
	}
}

func getAgentStat(now time.Time) {
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
		Version:   "0.0.0",
		TimeStamp: time.Now().Unix(),
	}
	bytesNet, _ := json.Marshal(report)
	log.Infof("%+v", string(bytesNet))
	tool.checkout([]string{"4001", "9001"})
}

//安装流量收集工具
func init() {
	if err := checkVnstat(); err != nil {
		if err := aptUpdate(); err != nil {
			log.Error(err)
		}
		if err := aptInstall("vnstat"); err != nil {
			log.Error(err)
		}
	}
}

func aptInstall(pkg string) error {
	cmd := exec.Command("apt-get", "install", "-y", pkg)
	log.Debugf("running command: %s", cmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		return errors.Wrapf(err, "failed to update %s", pkg)
	}
	return nil
}

func aptUpdate() error {
	cmd := exec.Command("apt-get", "update")
	log.Debugf("running command: %s", cmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		return errors.Wrapf(err, "failed to update metadata")
	}
	return nil
}
func checkVnstat() error {
	cmd := exec.Command("vnstat", "-v")
	log.Debugf("running command: %s", cmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		return errors.Wrapf(err, "vnstat not found")
	}
	return nil
}
func main() {
	wg := &sync.WaitGroup{}
	log.Info("++++++++++++++++++++++++++++++running++++++++++++++++++++++++++++++")
	wg.Add(3)
	agentCtx := context.TODO()
	go Startup(agentCtx, wg)
	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGTERM)
		<-sigs
		agentCtx.Done()
	}()
	wg.Wait()
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

// iptables -t filter -L INPUT  --line-number
func (p *PortTrafficStatistics) checkout(portlist []string) error {
	iptablePath, err := exec.LookPath("iptables")
	if err != nil {
		log.Error(err)
		return err
	}
	type Rule struct {
		Protocol string `json:"protocol"`
		Port     string `json:"port"`
		Dir      string `json:"dir"`
	}
	ruleMap := make(map[string][]Rule, 0)

	checkFun:= func(chain string) {
		var args []string
		name := iptablePath
		args = append(args, "-t", "filter", "-L", chain, "--line-number")
		c := exec.Command(name, args...)
		out, err := c.Output()
		if err != nil {
			log.Error(err)
			return
		}
		lines := strings.Split(string(out), "\n")
		if len(lines) < 3 {
			log.Error("1 annot parse iptables list information")
			return
		}
		mchain := chainNameRe.FindStringSubmatch(lines[0])
		if mchain == nil {
			log.Error("2 annot parse iptables list information")
			return
		}
		for _, line := range lines[2:] {
			stat := strings.Fields(line)
			if len(stat) != 7 {
				continue
			}
			sch := Rule{}
			sch.Protocol = stat[1]
			dports := strings.Split(stat[6], ":")
			if len(dports) != 2 {
				log.Errorf("annot parse iptables list information %+v", stat)
				continue
			}
			sch.Dir = dports[0]
			sch.Port = dports[1]
			if _, ok := ruleMap[sch.Port]; !ok {
				ruleMap[sch.Port] = make([]Rule, 0)
			}
			ruleMap[sch.Port] = append(ruleMap[sch.Port], sch)
		}
	}

	checkFun("INPUT")
	checkFun("OUTPUT")

	for _, port := range portlist {
		if _, ok := ruleMap[port]; ok {
			log.Infof("%+v",ruleMap[port])
			if len(ruleMap[port]) != 4 {
				p.deletePort([]string{port})
				p.addPort([]string{port})
			}
		} else {
			p.addPort([]string{port})
		}
	}
	return nil
}
