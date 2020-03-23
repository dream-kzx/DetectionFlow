package sniff

import (
	"FlowDetection/baseUtil"
	"FlowDetection/flowFeature"
	"github.com/google/gopacket/layers"
	"log"
	"sync"
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

type ConversationPool struct {
	TCPList     map[uint64]*TCPConversation
	UDPList     map[uint64]*UDPConversation
	quoteMap    map[uint64]int
	mutex       sync.Mutex
	countWindow *CountWindow
	timeWindow  *TimeWindow
	resultChan  chan interface{}
	featureChan chan *flowFeature.FlowFeature
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
		log.Println(conversation.ProtocolType, "(conversationPool.go 68)")
		if result := conversation.addPacket(tcp, connMsg); result != nil {
			tPool.mutex.Lock()
			mapList[converHash] = result
			tPool.quoteMap[converHash]++
			tPool.mutex.Unlock()
		}
	} else {
		nowTCPConversation := NewTCPConversation(fiveTuple, connMsg.Start, tcp.TransportFlow(), tPool.resultChan)
		tPool.mutex.Lock()
		mapList[converHash] = nowTCPConversation
		tPool.quoteMap[converHash]++
		tPool.mutex.Unlock()

		if result := nowTCPConversation.addPacket(tcp, connMsg); result != nil {
			tPool.mutex.Lock()
			mapList[converHash] = result
			tPool.quoteMap[converHash]++
			tPool.mutex.Unlock()
		}
	}

}

func (tPool *ConversationPool) addUDPPacket(udp layers.UDP,
	connMsg ConnMsg) {

	udpConversation := NewUDPConversation()

	baseFeature := udpConversation.AddPacket(udp, connMsg)

	tPool.resultChan <- baseFeature

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
			case *ResultChan:
				if resultChan := msg.(*ResultChan); resultChan != nil {
					tPool.mutex.Lock()
					num := tPool.quoteMap[resultChan.key]
					if num <= 1 {
						delete(tPool.TCPList, resultChan.key)
					} else {
						tPool.quoteMap[resultChan.key]--
					}
					tPool.mutex.Unlock()
					// resultChan.baseFeature.Print()
					feature.SetTCPBaseFeature(resultChan.baseFeature)
					tPool.countWindow.AddConversation(resultChan.baseFeature, feature)
					tPool.timeWindow.AddConversation(resultChan.baseFeature, feature)
					tPool.featureChan <- feature
					// feature.Print()
				}
			case *flowFeature.FlowFeature:
				if resultChan := msg.(*flowFeature.TCPBaseFeature); resultChan != nil {
					tPool.countWindow.AddConversation(resultChan, feature)
					tPool.timeWindow.AddConversation(resultChan, feature)
					tPool.featureChan <- feature
					// feature.Print()

				}
			}

		}
	}
}

func NewConversationPool(featureChan chan *flowFeature.FlowFeature) *ConversationPool {
	m := make(map[uint64]*TCPConversation)
	return &ConversationPool{
		TCPList:     m,
		resultChan:  make(chan interface{}, 4),
		quoteMap:    make(map[uint64]int),
		countWindow: NewCountWindow(),
		timeWindow:  NewTimeWindow(),
		featureChan: featureChan,
	}
}
