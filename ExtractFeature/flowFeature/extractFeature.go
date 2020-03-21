package flowFeature

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ExtractFeature struct {
	packets        []gopacket.Packet
	TcpBaseFeature TCPBaseFeature
	flows          map[gopacket.Flow][]gopacket.Packet
}

func (extractFeature *ExtractFeature) AddPacket(packet gopacket.Packet) {
	extractFeature.packets = append(extractFeature.packets, packet)
	if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
		if tcp, ok := tcp.(*layers.TCP); ok {
			extractFeature.flows[tcp.TransportFlow()] =
				append(extractFeature.flows[tcp.TransportFlow()], packet)
		}
	}
}

func (extractFeature *ExtractFeature) Extract() {
	//NewFlowFeature(nil,nil,nil,nil)
}
