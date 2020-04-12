package GUI

import (
	"FlowDetection/config"
	"github.com/ThomasRooney/gexpect"
	"regexp"
	"strconv"
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

	host, ok := h.manager.hostList[ip]
	if ok {
		host.Enabled = false
	}
	delete(h.manager.BlackList, ip)

	return Response{Code: 1, Message: "success"}
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
