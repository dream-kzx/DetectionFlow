package sniff

import (
	"github.com/google/gopacket/layers"
	"learn/baseUtil"
	"learn/config"
	"learn/flowFeature"
)

type ICMPConversation struct {
	Conversation
}

func NewICMPConversation() *ICMPConversation {
	return &ICMPConversation{
		Conversation{},
	}
}

func (i ICMPConversation) AddPacket(icmp layers.ICMPv4,
	connMsg ConnMsg) *flowFeature.TCPBaseFeature {

	fiveTuple := baseUtil.FiveTuple{
		SrcIP:        connMsg.srcIP,
		DstIP:        connMsg.dstIP,
		SrcPort:      0,
		DstPort:      0,
		ProtocolType: layers.IPProtocolUDP,
	}

	duration := connMsg.Last.Sub(connMsg.Start)

	service := GetICMPServiceType(icmp.TypeCode.Type(), icmp.TypeCode.Code())

	flag := baseUtil.SF

	if connMsg.dstIP == config.SERVERIP {
		i.SrcBytes += len(icmp.Payload)
	} else {
		i.DstBytes += len(icmp.Payload)
	}

	if connMsg.dstIP == connMsg.srcIP {
		i.Land = 1
	} else {
		i.Land = 0
	}

	i.WrongFragment += connMsg.wrong

	i.Urgent = 0

	tcpBaseFeature := flowFeature.NewTcpBaseFeature(fiveTuple, uint(duration), fiveTuple.ProtocolType,
		service, flag, i.SrcBytes, i.DstBytes, i.Land, i.WrongFragment, i.Urgent)

	return tcpBaseFeature
}
