package GUI

import (
	"github.com/asticode/go-astilectron"
	bootstrap "github.com/asticode/go-astilectron-bootstrap"
	"log"
)

type Result interface {
	add(*FlowResult)
}

type Manager struct {
	flowList       []*FlowResult
	connectionList map[string]*ConnectionResult
	hostList       map[string]*HostResult
	W              *astilectron.Window
}

func NewManager() *Manager {
	flowList := make([]*FlowResult, 0, 100)
	connectionList := make(map[string]*ConnectionResult, 100)
	hostList := make(map[string]*HostResult, 100)
	return &Manager{
		flowList:       flowList,
		connectionList: connectionList,
		hostList:       hostList,
	}
}

func (manager *Manager) SendHostMessage(key string) {
	host := manager.GetHost(key)

	err := bootstrap.SendMessage(manager.W, "hostList", host)
	if err != nil {
		log.Println(err)
	}
}

func (manager *Manager) SendConnectionMessage(key string) {
	connection := manager.GetConnection(key)
	err := bootstrap.SendMessage(manager.W, "connectionList", connection)
	if err != nil {
		log.Println(err)
	}
}

func (manager *Manager) AddFlow(flow *FlowResult) {
	manager.flowList = append(manager.flowList, flow)

	key := flow.SrcIP + flow.SrcPort
	connection, ok := manager.connectionList[key]
	if ok {
		connection.add(flow)
	} else {
		newConn := NewConnectionResult(*flow)
		newConn.add(flow)
		manager.connectionList[key] = newConn
	}

	key = flow.SrcIP
	host, ok := manager.hostList[key]
	if ok {
		host.add(flow)
	} else {
		newHost := NewHostResult(*flow)
		newHost.add(flow)
		manager.hostList[key] = newHost
	}
}

func (manager *Manager) GetConnection(key string) *ConnectionResult {
	value, ok := manager.connectionList[key]
	if ok {
		return value
	}
	return nil
}

func (manager *Manager) GetHost(key string) *HostResult {
	value, ok := manager.hostList[key]
	if ok {
		return value
	}
	return nil
}

type HostResult struct {
	FlowResult
	ConnNum      uint `json:"connNum"`
	normalNum    uint
	abnormalNum  uint
	AbnormalRate float64 `json:"abnormalRate"`
	Enabled      bool    `json:"enabled"`
}

func NewHostResult(flow FlowResult) *HostResult {
	return &HostResult{
		FlowResult: flow,
		Enabled:    false,
	}
}

func (h *HostResult) add(flow *FlowResult) {
	h.AttackType = flow.AttackType
	h.ConnNum++
	if flow.AttackType == "normal" {
		h.normalNum++
	} else {
		h.abnormalNum++
	}

	h.AbnormalRate = float64(h.abnormalNum) / float64(h.ConnNum)
}

type ConnectionResult struct {
	FlowResult
	ConnNum      uint `json:"connNum"`
	normalNum    uint
	abnormalNum  uint
	AbnormalRate float64 `json:"abnormalRate"`
	Enabled      bool    `json:"enabled"`
}

func NewConnectionResult(flow FlowResult) *ConnectionResult {
	return &ConnectionResult{
		FlowResult: flow,
		Enabled:    false,
	}
}

func (c *ConnectionResult) add(flow *FlowResult) {
	c.AttackType = flow.AttackType

	c.ConnNum++
	if flow.AttackType == "normal" {
		c.normalNum++
	} else {
		c.abnormalNum++
	}

	c.AbnormalRate = float64(c.abnormalNum) / float64(c.ConnNum)
}

type FlowResult struct {
	SrcIP      string `json:"ip"`
	SrcPort    string `json:"srcPort"`
	AttackType string `json:"attackType"`
}
