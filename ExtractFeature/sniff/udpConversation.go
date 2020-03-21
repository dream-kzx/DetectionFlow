package sniff

import (
	"github.com/google/gopacket/layers"
	"learn/baseUtil"
	"learn/config"
	"learn/flowFeature"
)

type UDPConversation struct {
	Conversation
	packetSum int
}

func (u *UDPConversation) AddPacket(udp layers.UDP, connMsg ConnMsg) *flowFeature.TCPBaseFeature {
	fiveTuple := baseUtil.FiveTuple{
		SrcIP:        connMsg.srcIP,
		DstIP:        connMsg.dstIP,
		SrcPort:      uint16(udp.SrcPort),
		DstPort:      uint16(udp.DstPort),
		ProtocolType: layers.IPProtocolUDP,
	}

	duration := connMsg.Last.Sub(connMsg.Start)

	service := GetUDPServiceType(fiveTuple)

	flag := baseUtil.SF

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

	u.Urgent = 0

	tcpBaseFeature := flowFeature.NewTcpBaseFeature(fiveTuple, uint(duration), fiveTuple.ProtocolType,
		service, flag, u.SrcBytes, u.DstBytes, u.Land, u.WrongFragment, u.Urgent)

	return tcpBaseFeature
}

func NewUDPConversation() *UDPConversation {
	return &UDPConversation{
		Conversation: Conversation{},
		packetSum:    0,
	}
}

//type UDPConversationList struct {
//	conversationList map[uint64]*UDPConversation
//}
//
//func (u *UDPConversationList) addPacket(udp layers.UDP, connMsg ConnMsg) {
//	fiveTuple := baseUtil.FiveTuple{
//		SrcIP:        connMsg.srcIP,
//		DstIP:        connMsg.dstIP,
//		SrcPort:      uint16(udp.SrcPort),
//		DstPort:      uint16(udp.DstPort),
//		ProtocolType: layers.IPProtocolUDP,
//	}
//
//	fiveTuple.FastHash()
//
//	udpConversation := UDPConversation{
//		Conversation: Conversation{
//			FiveTuple: fiveTuple,
//			StartTime: connMsg.Start,
//			LastTime:  connMsg.Last,
//		},
//	}
//
//	udpConversation.Service = GetUDPServiceType(fiveTuple)
//	udpConversation.packetSum++
//
//	udpConversation.WrongFragment += connMsg.wrong
//	if fiveTuple.SrcIP == fiveTuple.DstIP {
//		udpConversation.Land = 1
//	} else {
//		udpConversation.Land = 0
//	}
//
//	if connMsg.dstIP == config.SERVERIP {
//		udpConversation.SrcBytes += len(udp.Payload)
//	} else {
//		udpConversation.DstBytes += len(udp.Payload)
//	}
//
//}
