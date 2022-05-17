package main

import (
	"encoding/json"
	"errors"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	log "github.com/sirupsen/logrus"
	"os/exec"
)
// structure for vnstat result
type Date struct {
	Year  int `json:"year"`
	Month int `json:"month"`
	Day   int `json:"day"`
}

type Time struct {
	Hour    int `json:"hour"`
	Minutes int `json:"minutes"`
}

type Created struct {
	DateObj Date `json:"date"`
}

type Updated struct {
	DateObj Date `json:"date"`
	TimeObj Time `json:"time"`
}

type Total struct {
	RX int `json:"rx"`
	TX int `json:"tx"`
}

type Day struct {
	Id      int  `json:"id"`
	DateObj Date `json:"date"`
	RX      int  `json:"rx"`
	TX      int  `json:"tx"`
}

type Month struct {
	Id      int  `json:"id"`
	DateObj Date `json:"date"`
	RX      int  `json:"rx"`
	TX      int  `json:"tx"`
}

type Hour struct {
	Id      int  `json:"id"`
	DateObj Date `json:"date"`
	RX      int  `json:"rx"`
	TX      int  `json:"tx"`
}

type Traffic struct {
	TotalObj  Total   `json:"total"`
	DaysArr   []Day   `json:"days"`
	MonthsArr []Month `json:"months"`
	HoursArr  []Hour  `json:"hours"`
}

type Interfaces struct {
	Id         string  `json:"id"`
	Nick       string  `json:"nick"`
	CreatedObj Created `json:"created"`
	UpdatedObj Updated `json:"updated"`
	TrafficObj Traffic `json:"traffic"`
}

type VNResult struct {
	VNStatVersion string       `json:"vnstatversion"`
	JSONVersion   string       `json:"jsonversion"`
	InterfacesObj []Interfaces `json:"interfaces"`
}

// Structure for all network Interfaces
type NetInterface struct {
	Index int    `json:"index"`
	MTU   int    `json:"mtu"`
	Name  string `json:"name"`
}

type SystemInfo struct {
	MemoryStatus *mem.VirtualMemoryStat `json:"memory_status"`
	AvgLoad      *load.AvgStat          `json:"avg_load"`
	Process      *load.MiscStat         `json:"process"`
	NetSpeed     NetSpeed               `json:"net_speed"`
	CpuCount     int                    `json:"cpu_count"`
	CpuTimesStat cpu.TimesStat          `json:"cpu_times_stat"`
	DiskUsage    *disk.UsageStat        `json:"disk_usage"`
	NetInfo      NetInfo                `json:"net_info"`
	NetStat      net.IOCountersStat     `json:"net_stat"`
}

type NetSpeed struct {
	BytesSent   uint64 `json:"bytesSent"`   // number of bytes sent
	BytesRecv   uint64 `json:"bytesRecv"`   // number of bytes received
	PacketsSent uint64 `json:"packetsSent"` // number of packets sent
	PacketsRecv uint64 `json:"packetsRecv"` // number of packets received
}

type NetInfo struct {
	Status int32 `json:"status"`
}

type NodeStat struct {
	NodeID   int32      `json:"node_id"`
	NodeName string     `json:"node_name"`
	Stat     SystemInfo `json:"stat"`
	Time     int64      `json:"time"`
}

// This function will execute vnstat command
func VN(netInterface string) VNResult {
	cmd := exec.Command("vnstat", "-m", "-i", netInterface, "--json")
	stdout, err := cmd.Output()
	if err != nil {
		log.Errorf("get vnstat ret error %s", err.Error())
		return VNResult{}
	}
	err = cmd.Start()
	if err != nil {
		err = errors.New("COMMAND_ERROR")
	}
	defer cmd.Wait()
	b := []byte(stdout)
	var vnRes VNResult
	err = json.Unmarshal(b, &vnRes)
	if err != nil {
		log.Errorf("json.Unmarshal error %s", err.Error())
		return VNResult{}
	}
	return vnRes
}

// This function will execute a command that lists all available network interfaces
func GetAllNetInterfaces() []NetInterface {
	var allNetInterfaces []NetInterface
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Errorf("get net interfaces error %s", err.Error())
		return nil
	}
	for key := range interfaces {
		allNetInterfaces = append(allNetInterfaces, NetInterface{
			Index: interfaces[key].Index,
			MTU:   interfaces[key].MTU,
			Name:  interfaces[key].Name,
		})
	}
	return allNetInterfaces
}