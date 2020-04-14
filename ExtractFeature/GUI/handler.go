package GUI

import (
	"FlowDetection/config"
	"encoding/json"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/ThomasRooney/gexpect"
	"github.com/asticode/go-astilectron"
	bootstrap "github.com/asticode/go-astilectron-bootstrap"
)

var (
	BlackToSnifferChan chan *OperateSniffer
	AutoFilter *bool //自动加入黑名单
)

type Handler struct {
	Parameter          *Parameters
	manager            *Manager
}

func NewHandler(manager *Manager, blackToSnifferChan chan *OperateSniffer, autoFilter *bool) *Handler {
	handle := new(Handler)
	handle.manager = manager
	handle.Parameter = NewParameters()

	BlackToSnifferChan = blackToSnifferChan
	AutoFilter = autoFilter

	return handle
}

type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Payload interface{} `json:"payload"`
}

func (h *Handler) toFirstCharUpper(str string) string {
	r := []rune(str)
	if r[0] >= 97 && r[0] <= 122 {
		r[0] -= 32
	}
	return string(r)
}

func (h *Handler) HandleMessages(_ *astilectron.Window,
	messageIn bootstrap.MessageIn) (payload interface{}, handleErr error) {

	var data map[string]interface{}
	data = make(map[string]interface{})
	if err := json.Unmarshal(messageIn.Payload, &data); err != nil {
		payload = nil
		return
	}

	h.Parameter.Form(data)
	reflectVal := reflect.ValueOf(h)
	method := reflectVal.MethodByName(
		h.toFirstCharUpper(messageIn.Name) + "Handler")

	if method.IsValid() {
		retVal := method.Call(nil)
		return retVal[0].Interface().(Response), nil
	}
	return Response{Code: 0, Message: "Not Found"}, nil
}

func (h *Handler) AddFireWallInNoGUI(ip string) {
	_, ok := h.manager.BlackList[ip]
	if ok {
		return
	}

	err := addFireWall(ip)
	if err != nil {
		return
	}

	operateSniffer := &OperateSniffer{
		Operate: 1,
		IP:      ip,
	}
	BlackToSnifferChan <- operateSniffer

	h.manager.BlackList[ip] = struct{}{}
}

func (h *Handler) RemoveFirewallInNoGUI(ip string) {
	_, ok := h.manager.BlackList[ip]
	if !ok {
		return
	}

	err := removeFireWall(ip)
	if err != nil {
		return
	}

	operateSniffer := &OperateSniffer{
		Operate: 0,
		IP:      ip,
	}
	BlackToSnifferChan <- operateSniffer

	delete(h.manager.BlackList, ip)
}

func addFireWall(ip string) error {
	cmdStr := "sudo iptables -I INPUT -s " + ip + " -j DROP"
	child, err := gexpect.Spawn(cmdStr)
	if err != nil {
		return err
	}

	_ = child.SendLine(config.ServerRootPasswd)
	child.Interact()
	return nil
}

func removeFireWall(ip string) error {
	child, err := gexpect.Spawn("sudo iptables -L INPUT --line-numbers")
	if err != nil {
		return err
	}

	child.SendLine(config.ServerRootPasswd)

	_, reciever := child.AsyncInteractChannels()

	resultNum := make([]string, 0)

	for res := range reciever {

		if strings.Contains(res, ip) {
			regx, _ := regexp.Compile(`\d+`)
			r := regx.FindString(res)
			resultNum = append(resultNum, r)
		}
	}

	for i, number := range resultNum {
		n, err := strconv.Atoi(number)
		if err != nil {
			break
		}

		n -= i

		cmdStr := "sudo iptables -D INPUT " + strconv.Itoa(n)

		child, err := gexpect.Spawn(cmdStr)
		if err != nil {
			continue
		}

		child.SendLine(config.ServerRootPasswd)
		child.Interact()
	}

	child, err = gexpect.Spawn("sudo iptables -L INPUT --line-numbers")
	if err != nil {
		return err
	}
	child.SendLine(config.ServerRootPasswd)
	child.Interact()

	return nil
}
