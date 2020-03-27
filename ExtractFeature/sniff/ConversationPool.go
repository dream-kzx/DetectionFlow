package sniff

import (
	"FlowDetection/baseUtil"
	"FlowDetection/flowFeature"
	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"log"
	"time"
)

type ResultChan struct {
	key         uint64
	baseFeature *flowFeature.TCPBaseFeature
}

func NewResultChan(key uint64, baseFeature *flowFeature.TCPBaseFeature) *ResultChan {
	return &ResultChan{
		key:         key,
		baseFeature: baseFeature,
	}
}

type IPRefragKey struct {
	Id    uint16
	SrcIP [4]byte
}

type ConversationPool struct {
	FragmentList *ip4defrag.IPv4Defragmenter
	connMsgs     map[IPRefragKey]*ConnMsg
	TCPList      map[uint64]*TCPConversation
	UDPList      map[uint64]*UDPConversation
	mapQueue     *KeyQueue
	resultChan   chan interface{} //接收超时、连接结束的信道，传递的为baseFeature
	countWindow  *CountWindow
	timeWindow   *TimeWindow
	featureChan  chan *flowFeature.FlowFeature //返回特征的信道，传递的信道用来预测流量类型
}

func (tPool *ConversationPool) DisposePacket(packet gopacket.Packet) {
	//判断流量包网络层的类型，如果为ipv4，则继续执行
	ipv4 := packet.Layer(layers.LayerTypeIPv4)
	if ipv4 == nil {
		log.Println("(Sniffer.disposePacket) packet parsing fail!")
		log.Println(packet.LinkLayer().LayerType())
		return
	}
	//包的类型转换
	ipv4Layer, ok := ipv4.(*layers.IPv4)
	if !ok {
		log.Println("cast failed!")
		return
	}

	//记录每个IP的时间，主要用于IP分片重组，记录第一个分片和最后一个分配到达时间
	//通过IP数据包中，每个分片的ID是唯一标识的
	var srcIp, dstIp [4]byte
	copy(srcIp[:4], ipv4Layer.SrcIP)
	copy(dstIp[:4], ipv4Layer.DstIP)

	ipRefraKey := IPRefragKey{
		Id:    ipv4Layer.Id,
		SrcIP: srcIp,
	}

	t, ok := tPool.connMsgs[ipRefraKey]
	if ok {
		t.Last = packet.Metadata().Timestamp
	} else {
		now := &ConnMsg{
			srcIP: srcIp,
			dstIP: dstIp,
			Start: packet.Metadata().Timestamp,
			Last:  packet.Metadata().Timestamp,
		}
		tPool.connMsgs[ipRefraKey] = now
	}

	//对ip分片进行头部校验
	if !IPCheckSum(ipv4Layer.Contents[0:20]) {
		tPool.connMsgs[ipRefraKey].wrong++
	}

	//检测是否需要ip分片重组
	ipPacket, err := tPool.FragmentList.DefragIPv4WithTimestamp(
		ipv4Layer, packet.Metadata().Timestamp)
	if err != nil {
		log.Println("该包为IP分片！(ConversationPool.go 84)")
		tPool.checkTimeout(packet.Metadata().Timestamp)
		return
	}

	tPool.checkTimeout(packet.Metadata().Timestamp)

	payload := ipPacket.Payload

	switch ipPacket.Protocol {
	case layers.IPProtocolICMPv4:
		log.Println("icmp (ConversationPool.go 92)")
		p := gopacket.NewPacket(payload, layers.LayerTypeICMPv4, gopacket.Default)
		if layer := p.Layer(layers.LayerTypeICMPv4); layer != nil {
			if icmp, ok := layer.(*layers.ICMPv4); ok {
				tPool.addICMPPacket(*icmp, *tPool.connMsgs[ipRefraKey])
			}
		}
	case layers.IPProtocolTCP:
		log.Println("tcp (ConversationPool.go 100)")
		p := gopacket.NewPacket(payload, layers.LayerTypeTCP, gopacket.Default)
		if layer := p.Layer(layers.LayerTypeTCP); layer != nil {
			if tcp, ok := layer.(*layers.TCP); ok {
				tPool.addTCPPacket(*tcp, *tPool.connMsgs[ipRefraKey])
			}
		}

	case layers.IPProtocolUDP:
		log.Println("UDP (ConversationPool.go 109)")
		p := gopacket.NewPacket(payload, layers.LayerTypeUDP, gopacket.Default)
		if layer := p.Layer(layers.LayerTypeUDP); layer != nil {
			if udp,ok := layer.(*layers.UDP); ok {
				tPool.addUDPPacket(*udp, *tPool.connMsgs[ipRefraKey])
			}
		}

	default:
		return
	}

	delete(tPool.connMsgs, ipRefraKey)

}

func (tPool *ConversationPool) checkTimeout(now time.Time) {
	mapQueue := tPool.mapQueue
	log.Println(mapQueue.Size, "(ConversationPool.go 127)")
	if mapQueue.Size == 3 {
		log.Println("11111")
	}
	for mapQueue.Size > 0 {
		key := mapQueue.Front()
		t, ok := tPool.TCPList[key]
		if ok {
			interval := now.Sub(t.LastTime)
			if interval > 2*1000*1000*1000 {
				mapQueue.Pop()
				t.ExtractBaseFeature()
				delete(tPool.TCPList, key)
				log.Println("Delete TcpList 136 Line")

			} else {
				return
			}
		} else {
			u, ok := tPool.UDPList[key]
			if ok {
				interval := now.Sub(u.LastTime)
				if interval > 2*1000*1000*1000 {
					mapQueue.Pop()
					u.ExtractBaseFeature()
					delete(tPool.UDPList, key)
				}else{
					return
				}
			}else{
				log.Println("ConversationPool.go 166")
			}
		}
	}
}

func (tPool *ConversationPool) addTCPPacket(tcp layers.TCP,
	connMsg ConnMsg) {
	mapList := tPool.TCPList

	fiveTuple := baseUtil.FiveTuple{
		SrcIP:        connMsg.srcIP,
		DstIP:        connMsg.dstIP,
		SrcPort:      uint16(tcp.SrcPort),
		DstPort:      uint16(tcp.DstPort),
		ProtocolType: layers.IPProtocolTCP,
	}

	converHash := fiveTuple.FastHash()

	conversation, ok := mapList[converHash]
	if ok {
		tPool.mapQueue.ResetValue(converHash)

		// log.Println(conversation.ProtocolType, "(conversationPool.go 68)")
		result, finish := conversation.addPacket(tcp, connMsg)
		if result != nil {
			mapList[converHash] = result
		}
		if finish {
			conversation.ExtractBaseFeature()
			tPool.mapQueue.RemoveValue(converHash)
			delete(mapList, converHash)
		}

	} else {
		nowTCPConversation := NewTCPConversation(fiveTuple, connMsg.Start, tcp.TransportFlow(), tPool.resultChan)
		mapList[converHash] = nowTCPConversation
		tPool.mapQueue.Push(converHash)

		result, finish := nowTCPConversation.addPacket(tcp, connMsg)
		if result != nil {
			mapList[converHash] = result
		}
		if finish {
			nowTCPConversation.ExtractBaseFeature()
			tPool.mapQueue.RemoveValue(converHash)
			delete(mapList, converHash)
		}
	}

}

func (tPool *ConversationPool) addUDPPacket(udp layers.UDP,
	connMsg ConnMsg) {
		mapList := tPool.UDPList

		fiveTuple := baseUtil.FiveTuple{
			SrcIP:        connMsg.srcIP,
			DstIP:        connMsg.dstIP,
			SrcPort:      uint16(udp.SrcPort),
			DstPort:      uint16(udp.DstPort),
			ProtocolType: layers.IPProtocolUDP,
		}

		converHash := fiveTuple.FastHash()

		conversation, ok := mapList[converHash]
		if ok {
			tPool.mapQueue.ResetValue(converHash)
			conversation.AddPacket(udp, connMsg)
		} else {
			nowUDPConversation := NewUDPConversation(fiveTuple, tPool.resultChan)
			mapList[converHash] = nowUDPConversation
			tPool.mapQueue.Push(converHash)
			nowUDPConversation.AddPacket(udp, connMsg)
		}
}

func (tPool *ConversationPool) addICMPPacket(icmp layers.ICMPv4, msg ConnMsg) {
	icmpConversation := NewICMPConversation()
	baseFeature := icmpConversation.AddPacket(icmp, msg)

	tPool.resultChan <- baseFeature
}

func (tPool *ConversationPool) checkResultChan() {

	for {
		select {
		case msg := <-tPool.resultChan:
			feature := flowFeature.NewFlowFeature()
			switch msg.(type) {

			case *flowFeature.TCPBaseFeature:
				if resultChan := msg.(*flowFeature.TCPBaseFeature); resultChan != nil {
					feature.SetTCPBaseFeature(resultChan)

					tPool.countWindow.AddConversation(resultChan, feature)
					tPool.timeWindow.AddConversation(resultChan, feature)
					tPool.featureChan <- feature
					// feature.Print()
				}

			default:
				log.Println("其他特征类型，（ConversationPool.go 245）")
			}

		}
	}
}

func NewConversationPool(featureChan chan *flowFeature.FlowFeature) *ConversationPool {
	return &ConversationPool{
		FragmentList: ip4defrag.NewIPv4Defragmenter(),
		connMsgs:     make(map[IPRefragKey]*ConnMsg),
		TCPList:      make(map[uint64]*TCPConversation),
		UDPList:      make(map[uint64]*UDPConversation),
		mapQueue:     NewKeyQueue(),
		resultChan:   make(chan interface{}, 4),
		countWindow:  NewCountWindow(),
		timeWindow:   NewTimeWindow(),
		featureChan:  featureChan,
	}
}
