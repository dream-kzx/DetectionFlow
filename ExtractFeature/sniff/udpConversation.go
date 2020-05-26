package sniff

import (
	"FlowDetection/baseUtil"
	"FlowDetection/config"
	"FlowDetection/flowFeature"
	"github.com/google/gopacket/layers"
)

type UDPConversation struct {
	Conversation
	packetSum int
	poolChan  chan interface{}
}

func (u *UDPConversation) AddPacket(udp layers.UDP, connMsg ConnMsg) {
	u.packetSum++

	if u.packetSum == 1 {
		if u.SrcIP == config.SERVERIP{
			u.SrcIP,u.DstIP = u.DstIP,u.SrcIP
		}

		u.StartTime = connMsg.Start
		u.Service = GetUDPServiceType(u.FiveTuple)

		u.Flag = baseUtil.SF
		u.Urgent = 0
	}
	u.LastTime = connMsg.Last

	if connMsg.dstIP == config.SERVERIP {
		u.SrcBytes += len(udp.Payload)
	} else {
		u.DstBytes += len(udp.Payload)
	}

	if connMsg.dstIP == connMsg.srcIP {
		u.Land = 1
	} else {
		u.Land = 0
	}

	u.WrongFragment += connMsg.wrong
}

func (u *UDPConversation) ExtractBaseFeature() {

	duration := uint(u.LastTime.Sub(u.StartTime)/1000000000)

	tcpFeature := flowFeature.NewTcpBaseFeature(u.FiveTuple, duration, u.FiveTuple.ProtocolType,
		u.Service, u.Flag, u.SrcBytes, u.DstBytes, u.Land, u.WrongFragment, u.Urgent)
	tcpFeature.StartTime = u.StartTime
	tcpFeature.LastTime = u.LastTime

	u.poolChan <- tcpFeature

}

func NewUDPConversation(tuple baseUtil.FiveTuple, poolChan chan interface{}) *UDPConversation {
	return &UDPConversation{
		Conversation: Conversation{
			FiveTuple: tuple,
		},
		poolChan:  poolChan,
		packetSum: 0,
	}
}
