package main

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"github.com/coreos/go-iptables/iptables"
	"os/exec"
	"regexp"
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

	log.Info("=========================================================================")
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
	stats, err := iptablesObject.StructuredStats("filter", "INPUT")
	if err != nil {
		log.Error(err)
		return
	}
	log.Infof("%+v ",stats)
	log.Info("=========================================================================")
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

const measurement = "iptables"

var errParse = errors.New("Cannot parse iptables list information")
var chainNameRe = regexp.MustCompile(`^Chain\s+(\S+)`)
var fieldsHeaderRe = regexp.MustCompile(`^\s*pkts\s+bytes\s+target`)
var valuesRe = regexp.MustCompile(`^\s*([0-9]+)\s+([0-9]+)\s+.*?(/\*\s(.*)\s\*/)?$`)


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
		log.Infof("%+v",line)
		matches := valuesRe.FindStringSubmatch(line)
		if len(matches) != 5 {
			log.Infof("%+v",matches)
			continue
		}
		log.Info("=========================================================================")
		pkts := matches[1]
		bytes := matches[2]
		target := matches[3]
		comment := matches[4]
		log.Infof("%+v, pkts: %+v , bytes: %+v , target: %+v, comment:%+v ",matches[0],pkts,bytes,target,comment)
	}
	return nil
}