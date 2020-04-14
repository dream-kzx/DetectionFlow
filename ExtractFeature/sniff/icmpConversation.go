package sniff

import (
	"FlowDetection/baseUtil"
	"FlowDetection/config"
	"FlowDetection/flowFeature"
	"github.com/google/gopacket/layers"
)

type ICMPConversation struct {
	Conversation
	poolChan chan interface{} //用于结束后返回结果到pool
	PacketSum uint
	Direction uint8 //server -> client 0, clinet -> server 1
}

func NewICMPConversation(poolChan chan interface{}) *ICMPConversation {
	return &ICMPConversation{
		Conversation: Conversation{},
		poolChan: poolChan,
	}
}

func (i *ICMPConversation) AddPacket(icmp layers.ICMPv4,
	connMsg ConnMsg) bool {

	if i.PacketSum == 0 {
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

		i.FiveTuple = fiveTuple

		i.StartTime = connMsg.Start

		i.Flag = baseUtil.SF

		if connMsg.dstIP == connMsg.srcIP {
			i.Land = 1
		} else {
			i.Land = 0
		}

		i.Urgent = 0
	}

	i.LastTime = connMsg.Last

	service := GetICMPServiceType(icmp.TypeCode.Type(), icmp.TypeCode.Code())

	if i.PacketSum == 0 && service == baseUtil.SRV_ECO_I {
		if i.Direction == 0 {
			i.Service = baseUtil.SRV_ECR_I
		} else {
			i.Service = baseUtil.SRV_ECO_I
		}
	} else if i.PacketSum > 0 && service == baseUtil.SRV_ECR_I {

	} else {
		i.Service = service
	}

	if connMsg.dstIP == config.SERVERIP {
		i.SrcBytes += len(icmp.Payload)
	} else {
		i.DstBytes += len(icmp.Payload)
	}

	i.WrongFragment += connMsg.wrong

	if i.PacketSum == 0 {
		i.PacketSum++
		return false
	} else {
		return true
	}
}

func (i *ICMPConversation) IsSameConversation(msg ConnMsg) bool {
	var direction uint8
	if msg.srcIP == config.SERVERIP {
		direction = 0
	} else {
		direction = 1
	}

	if i.Direction == direction {
		return false
	}else{
		return true
	}

}

func (i *ICMPConversation) ExtractFeature(){
	duration := i.LastTime.Sub(i.StartTime)

	tcpBaseFeature := flowFeature.NewTcpBaseFeature(i.FiveTuple, uint(duration), i.FiveTuple.ProtocolType,
		i.Service, i.Flag, i.SrcBytes, i.DstBytes, i.Land, i.WrongFragment, i.Urgent)

	i.poolChan <- tcpBaseFeature
}
