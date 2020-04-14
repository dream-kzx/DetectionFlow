package GUI

import (
	"github.com/asticode/go-astilectron"
	bootstrap "github.com/asticode/go-astilectron-bootstrap"
	"log"
)



type FlowResult struct {
	SrcIP      string `json:"ip"`
	SrcPort    string `json:"srcPort"`
	AttackType string `json:"attackType"`
}

type Result interface {
	add(*FlowResult)
}

type Manager struct {
	flowList       []*FlowResult
	BlackList      map[string]interface{}
	hostList       map[string]*HostResult
	W              *astilectron.Window
}

func NewManager() *Manager {
	flowList := make([]*FlowResult, 0, 100)
	hostList := make(map[string]*HostResult, 100)
	blackList := make(map[string]interface{})

	return &Manager{
		flowList:       flowList,
		hostList:       hostList,
		BlackList:      blackList,
	}
}

func (manager *Manager) SendHostMessage(key string) {
	host := manager.GetHost(key)

	err := bootstrap.SendMessage(manager.W, "hostList", host)
	if err != nil {
		log.Println(err)
	}
}


func (manager *Manager) AddFlow(flow *FlowResult) {
	manager.flowList = append(manager.flowList, flow)


	key := flow.SrcIP
	host, ok := manager.hostList[key]
	if ok {
		host.add(flow)

		abnormalNum := host.GetAbnormalNum()
		// log.Println(abnormalNum)
		if abnormalNum >1000 && *AutoFilter{

			_, ok := manager.BlackList[key]
			if !ok {
				// log.Println("》》》》》》》》》》》》》》》》》》》》》》》》》》》》》》加入黑名单")
				err:=addFireWall(key)
				if err!=nil{
					log.Println(err)
				}else{
					operateSniffer := &OperateSniffer{
						Operate: 1,
						IP:      key,
					}
					BlackToSnifferChan <- operateSniffer
				}
				host.Enabled = true
				manager.BlackList[key]=struct{}{}
			}
		}
	} else {
		newHost := NewHostResult(*flow)
		newHost.add(flow)
		manager.hostList[key] = newHost
	}
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

func (h HostResult) GetAbnormalNum() uint{
	return h.abnormalNum
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


