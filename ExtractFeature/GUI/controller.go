package GUI

import (
	"strings"
)

func (h *Handler) AddBlackListHandler() Response {
	ip, _ := h.Parameter.GetString("ip", "")
	if ip == "" {
		return Response{Code: 0, Message: "Ip cannot be empty"}
	}
	ip = strings.Trim(ip, " ")
	if ip == "" {
		return Response{Code: 0, Message: "Ip cannot be empty"}
	}

	if _, ok := h.manager.BlackList[ip]; ok {
		return Response{Code: 1, Message: "success"}
	}

	err := addFireWall(ip)
	if err != nil {
		return Response{Code: 0, Message: "Add fireWall Fail!"}
	}

	operateSniffer := &OperateSniffer{
		Operate: 1,
		IP:      ip,
	}
	BlackToSnifferChan <- operateSniffer

	host, ok := h.manager.hostList[ip]
	if ok {
		host.Enabled = true
	}

	h.manager.BlackList[ip] = struct{}{}

	return Response{Code: 1, Message: "success"}
}

func (h *Handler) RemoveBlackListHandler() Response {
	ip, _ := h.Parameter.GetString("ip", "")
	if ip == "" {
		return Response{Code: 0, Message: "Ip cannot be empty"}
	}
	ip = strings.Trim(ip, " ")
	if ip == "" {
		return Response{Code: 0, Message: "Ip cannot be empty"}
	}

	if _, ok := h.manager.BlackList[ip]; !ok {
		return Response{Code: 1, Message: "success"}
	}

	err := removeFireWall(ip)
	if err != nil {
		return Response{Code: 0, Message: "Add fireWall Fail!"}
	}

	operateSniffer := &OperateSniffer{
		Operate: 0,
		IP:      ip,
	}
	BlackToSnifferChan <- operateSniffer

	host, ok := h.manager.hostList[ip]
	if ok {
		host.Enabled = false
	}

	delete(h.manager.BlackList, ip)

	return Response{Code: 1, Message: "success"}
}
