package sniff

import (
	"FlowDetection/baseUtil"
	"FlowDetection/config"
	"FlowDetection/flowFeature"
	"github.com/google/gopacket/layers"
)

type ICMPConversation struct {
	Conversation
	PacketSum uint
	Direction uint8  //server -> client 0, clinet -> server 1
}

func NewICMPConversation() *ICMPConversation {
	return &ICMPConversation{
		Conversation: Conversation{},
	}
}

func (i *ICMPConversation) AddPacket(icmp layers.ICMPv4,
	connMsg ConnMsg)  {

	fiveTuple := baseUtil.FiveTuple{
		SrcIP:        connMsg.srcIP,
		DstIP:        connMsg.dstIP,
		SrcPort:      0,
		DstPort:      0,
		ProtocolType: layers.IPProtocolICMPv4,
	}

	if connMsg.srcIP == config.SERVERIP {
		fiveTuple.SrcIP = connMsg.dstIP
		fiveTuple.DstIP = connMsg.srcIP

		i.Direction = 0
	}else{
		i.Direction = 1
	}



	if i.PacketSum == 0{
		i.StartTime = connMsg.Start
		i.LastTime = connMsg.Last
	}else{
		i.LastTime = connMsg.Last
	}

	service := GetICMPServiceType(icmp.TypeCode.Type(), icmp.TypeCode.Code())

	if service == baseUtil.SRV_ECO_I && i.Direction == 0{
		service = baseUtil.SRV_ECR_I
	}else if service == baseUtil.SRV_ECO_I && i.Direction == 1{
		service = baseUtil.SRV_ECO_I
	}

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


}


func (i *ICMPConversation) ExtractFeature() *flowFeature.TCPBaseFeature{
	duration := i.LastTime.Sub(i.StartTime)

	tcpBaseFeature := flowFeature.NewTcpBaseFeature(fiveTuple, uint(duration), fiveTuple.ProtocolType,
	service, flag, i.SrcBytes, i.DstBytes, i.Land, i.WrongFragment, i.Urgent)

	return tcpBaseFeature
}