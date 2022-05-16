package main

import (
	log "github.com/sirupsen/logrus"
	"os/exec"
)

func main() {
	tool := PortTrafficStatistics{}
	if err := tool.addPort([]string{"2348", "8086"}); err != nil {
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
	}
}

type PortTrafficStatistics struct {
}

func (p *PortTrafficStatistics) addPort(ports []string) error {
	for _, port := range ports {
		inTcp, err := exec.Command("iptables", "-I", "INPUT", "-p", "tcp", "--dport", port).Output()
		if err != nil {
			log.Error(err)
			return err
		}
		log.Infof("%+v", inTcp)
		inUdp, err := exec.Command("iptables", "-I", "INPUT", "-p", "udp", "--dport", port).Output()
		if err != nil {
			log.Error(err)
			return err
		}
		log.Infof("%+v", inUdp)
		outTcp, err := exec.Command("iptables", "-I", "OUTPUT", "-p", "tcp", "--sport", port).Output()
		if err != nil {
			log.Error(err)
			return err
		}
		log.Infof("%+v", outTcp)
		outUdp, err := exec.Command("iptables", "-I", "OUTPUT", "-p", "udp", "--sport", port).Output()
		if err != nil {
			log.Error(err)
			return err
		}
		log.Infof("%+v", outUdp)
	}
	return nil
}

func (p *PortTrafficStatistics) deletePort(ports []string) error {
	for _, port := range ports {
		//iptables -D INPUT -p tcp --dport $ports
		inTcp, err := exec.Command("iptables", "-D", "INPUT", "-p", "tcp", "--dport", port).Output()
		if err != nil {
			log.Error(err)
			return err
		}
		log.Infof("%+v", inTcp)
		//iptables -D INPUT -p udp --dport $ports
		inUdp, err := exec.Command("iptables", "-D", "INPUT", "-p", "udp", "--dport", port).Output()
		if err != nil {
			log.Error(err)
			return err
		}
		log.Infof("%+v", inUdp)
		//iptables -D OUTPUT -p tcp --sport $ports
		outTcp, err := exec.Command("iptables", "-D", "OUTPUT", "-p", "tcp", "--sport", port).Output()
		if err != nil {
			log.Error(err)
			return err
		}
		log.Infof("%+v", outTcp)
		//iptables -D OUTPUT -p udp --sport $ports
		outUcp, err := exec.Command("iptables", "-D", "OUTPUT", "-p", "udp", "--sport", port).Output()
		if err != nil {
			log.Error(err)
			return err
		}
		log.Infof("%+v", outUcp)
	}
	return nil
}

func (p *PortTrafficStatistics) clearAll() error {
	output, err := exec.Command("iptables", "-Z").Output()
	if err != nil {
		log.Error(err)
		return err
	}
	log.Infof("%+v", output)
	return nil
}
