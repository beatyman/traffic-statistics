package main

import (
	"errors"
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	log "github.com/sirupsen/logrus"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)
//https://github.com/seal0207/Port-traffic-statistics/blob/main/Port-.sh
//https://github.com/dominikh/simple-router/blob/92e945cdbf054d28b31f3906423ff08265ca4837/traffic/statistics.go
func main() {
	tool := PortTrafficStatistics{}
	tool.readStatistics()
	time.Sleep(time.Minute)
	tool.readStatistics()
	time.Sleep(time.Minute)
	tool.readStatistics()
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
	Packets     uint64     `json:"pkts"`
	Bytes       uint64     `json:"bytes"`
	Protocol    string     `json:"prot"`
	Port        string     `json:"port"`
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

func (p *PortTrafficStatistics)readStatistics () {
	log.Infof("解析流量数据")
	data,err:=p.chainList("filter", "INPUT")
	if err != nil {
		log.Error(err)
		return
	}
	err = p.parse(data)
	if err != nil {
		return
	}
	iptablesObject, err := iptables.New()
	if err != nil {
		log.Error(err)
		return
	}
	data1,err:=iptablesObject.Stats("filter", "INPUT")
	if err != nil {
		log.Error(err)
		return
	}
	log.Infof("%+v ",data1)
	for _,d:=range data1{
		sts,err:=p.ParseStat(d)
		if err != nil {
			log.Error(err)
		}else {
			log.Infof("%+v",sts)
		}
	}
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


var errParse = errors.New("Cannot parse iptables list information")
var chainNameRe = regexp.MustCompile(`^Chain\s+(\S+)`)
var fieldsHeaderRe = regexp.MustCompile(`^\s*pkts\s+bytes\s+target`)
var valuesRe = regexp.MustCompile(`^\s*([0-9]+)\s+([0-9]+)\s+.*?(/\*\s(.*)\s\*/)?$`)
var iptablesRuleFieldSeparator = regexp.MustCompile("[[:blank:]]+")
var iptablesRuleDPortRegexp = regexp.MustCompile(`(tcp|udp) dpts?:(?P<minPort>\d+)(:(?P<maxPort>\d+))?`)
var iptablesRuleStateRegexp = regexp.MustCompile(`state [[:alpha:]]+(,[[:alpha:]]+)*`)
var iptablesRuleStatsInfoRegexp = regexp.MustCompile(`^ ?\d+[A-Z]? \d+[A-Z]? `)

func (p *PortTrafficStatistics) parse(data string) error {
	lines := strings.Split(data, "\n")
	if len(lines) < 3 {
		return nil
	}
	mchain := chainNameRe.FindStringSubmatch(lines[0])
	if mchain == nil {
		return errParse
	}
	if !fieldsHeaderRe.MatchString(lines[1]) {
		return errParse
	}
	for _, line := range lines[2:] {
		fields:=strings.Fields(line)
		sts,err:=p.ParseStat(fields)
		if err!=nil{
			return errParse
		}
		log.Infof("sts :   %+v",sts)
	}
	return nil
}
// pkts      bytes target     prot opt in     out     source               destination
func (p *PortTrafficStatistics) ParseStat(stat []string) (parsed Stat, err error) {
	if len(stat) < 10 {
		return parsed, fmt.Errorf("stat contained fewer fields than expected")
	}
	log.Infof("%+v",stat)
	// Convert the fields that are not plain strings
	parsed.Packets, err = strconv.ParseUint(stat[0], 0, 64)
	if err != nil {
		return parsed, fmt.Errorf(err.Error(), "could not parse packets")
	}
	parsed.Bytes, err = strconv.ParseUint(stat[1], 0, 64)
	if err != nil {
		return parsed, fmt.Errorf(err.Error(), "could not parse bytes")
	}
	parsed.Protocol = stat[2]
	var dports [2]int
	dports, err = parseRuleDPorts(stat[9])
	if err != nil {
		return  parsed,err
	}
	parsed.Port=strconv.Itoa(dports[1])
	return parsed, nil
}
func parseRuleDPorts(r string) ([2]int, error) {
	log.Infof("r: %+v",r)
	match := iptablesRuleDPortRegexp.FindStringSubmatch(r)
	dports := [2]int{0, 0}
	for i, name := range iptablesRuleDPortRegexp.SubexpNames() {
		var err error
		switch name {
		case "minPort":
			dports[0], err = strconv.Atoi(match[i])
			if err != nil {
				return dports, fmt.Errorf("rule '%s' has invalid destination %s specification '%s'", r, name, match[i])
			}
		case "maxPort":
			dports[1], _ = strconv.Atoi(match[i])
			if err != nil {
				dports[1] = 0
			}
		default:
		}
	}
	if dports[1] == 0 {
		dports[1] = dports[0]
	}
	return dports, nil
}