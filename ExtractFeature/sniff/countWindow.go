package sniff

import "FlowDetection/flowFeature"

const WindowSize = 256

type HostServiceKey struct {
	IP      string
	Service uint8
}

type HostSrcPortKey struct {
	IP      string
	SrcPort uint16
}

func NewServiceHostKey(IP string, Service uint8) *HostServiceKey {
	return &HostServiceKey{
		IP:      IP,
		Service: Service,
	}
}

type CountWindow struct {
	conversationQueue  *Queue
	sameHostMap        map[string][]*flowFeature.TCPBaseFeature
	sameHostServiceMap map[HostServiceKey][]*flowFeature.TCPBaseFeature
	sameHostSrcPortMap map[HostSrcPortKey]int
	sameSrcIPMap       map[string]int
}

func NewCountWindow() *CountWindow {
	return &CountWindow{
		conversationQueue:  NewQueue(),
		sameHostMap:        make(map[string][]*flowFeature.TCPBaseFeature),
		sameHostServiceMap: make(map[HostServiceKey][]*flowFeature.TCPBaseFeature),
		sameHostSrcPortMap: make(map[HostSrcPortKey]int),
		sameSrcIPMap:       make(map[string]int),
	}
}

func (c *CountWindow) AddConversation(tcpBaseFeature *flowFeature.TCPBaseFeature,
	feature *flowFeature.FlowFeature) {

	c.calculateFeature(tcpBaseFeature, feature)
	if c.conversationQueue.Size > WindowSize {
		c.removeInMap()
	}
	c.addInMap(tcpBaseFeature)
}

func (c *CountWindow) removeInMap() {
	tcpBaseFeature := c.conversationQueue.Front()
	c.conversationQueue.Pop()

	//sameHostMap
	dstIPStr := string(tcpBaseFeature.DstIP[:])
	sameHostList, ok := c.sameHostMap[dstIPStr]
	if ok {
		for i, sameHost := range sameHostList {
			if sameHost == tcpBaseFeature {
				if len(sameHostList) == 1 {
					delete(c.sameHostMap, dstIPStr)
				} else {
					sameHostList = append(sameHostList[:i], sameHostList[i+1:]...)
				}
				break
			}
		}
	}

	//sameHostServiceMap
	hostService := HostServiceKey{
		IP:      dstIPStr,
		Service: tcpBaseFeature.Service,
	}
	hostServiceList, ok := c.sameHostServiceMap[hostService]
	if ok {
		for k, v := range hostServiceList {
			if v == tcpBaseFeature {
				if len(hostServiceList) == 1 {
					delete(c.sameHostServiceMap, hostService)
				} else {
					hostServiceList = append(hostServiceList[:k], hostServiceList[k+1:]...)
				}
				break
			}
		}
	}

	//sameHostSrcPortMap
	hostSrcPort := HostSrcPortKey{
		IP:      dstIPStr,
		SrcPort: tcpBaseFeature.SrcPort,
	}
	c.sameHostSrcPortMap[hostSrcPort]--
	if c.sameHostSrcPortMap[hostSrcPort] == 0 {
		delete(c.sameHostSrcPortMap, hostSrcPort)
	}

	//sameSrcIPMap
	srcIPStr := string(tcpBaseFeature.SrcIP[:])
	c.sameSrcIPMap[srcIPStr]--
	if c.sameSrcIPMap[srcIPStr] == 0 {
		delete(c.sameSrcIPMap, srcIPStr)
	}

}

func (c *CountWindow) calculateFeature(tcpBaseFeature *flowFeature.TCPBaseFeature,
	feature *flowFeature.FlowFeature) {
	dstIPStr := string(tcpBaseFeature.DstIP[:])
	srcPort := tcpBaseFeature.SrcPort
	service := tcpBaseFeature.Service
	serviceHost := HostServiceKey{
		IP:      dstIPStr,
		Service: service,
	}
	hostSrcPort := HostSrcPortKey{
		IP:      dstIPStr,
		SrcPort: srcPort,
	}

	sameHostList := c.sameHostMap[dstIPStr]
	dstHostCount := len(sameHostList) //32 P(A)

	//dstServiceCount := c.sameServiceMap[service] //P(B)
	dstHostServiceList := c.sameHostServiceMap[serviceHost]
	dstHostSrvCount := len(dstHostServiceList) //33 P(AB)

	dstHostSameSrvRate := float64(dstHostSrvCount) / WindowSize              //34 P(AB)/256
	dstHostDiffSrvRate := float64(dstHostCount-dstHostSrvCount) / WindowSize //35 (P(A)-P(AB))/256

	dstHostSameSrcPortCount := c.sameHostSrcPortMap[hostSrcPort]
	dstHostSameSrcPortRate := float64(dstHostSameSrcPortCount) / WindowSize //36 P(AC)/256

	diffSrcHostCount := 0
	hostSrvSErrorCount := 0
	hostSrvRErrorCount := 0
	for _, l := range dstHostServiceList {
		if l.SrcIP != tcpBaseFeature.SrcIP {
			diffSrcHostCount++
		}
		if l.IsSerror() {
			hostSrvSErrorCount++
		}
		if l.IsRerror() {
			hostSrvRErrorCount++
		}
	}

	dstHostSrvDiffHostRate := 0.0
	if dstHostSrvCount != 0 {
		dstHostSrvDiffHostRate = float64(diffSrcHostCount) / float64(dstHostSrvCount) //37
	}

	hostSErrorCount := 0
	hostRErrorCount := 0
	for _, l := range sameHostList {
		if l.IsSerror() {
			hostSErrorCount++
		}
		if l.IsRerror() {
			hostRErrorCount++
		}
	}

	dstHostSErrorRate := 0.0
	dstHostRErrorRate := 0.0
	if dstHostCount != 0 {
		dstHostSErrorRate = float64(hostSErrorCount) / float64(dstHostCount) //38

		dstHostRErrorRate = float64(hostRErrorCount) / float64(dstHostCount) //40
	}

	dstHostSrvSErrorRate := 0.0
	dstHostSrvRErrorRate := 0.0
	if dstHostSrvCount != 0 {
		dstHostSrvSErrorRate = float64(hostSrvSErrorCount) / float64(dstHostSrvCount) //39
		dstHostSrvRErrorRate = float64(hostSrvRErrorCount) / float64(dstHostSrvCount) //41
	}

	hostFlowFeature := flowFeature.NewHostFlowFeature(uint16(dstHostCount), uint16(dstHostSrvCount),
		float32(dstHostSameSrvRate), float32(dstHostDiffSrvRate), float32(dstHostSameSrcPortRate),
		float32(dstHostSrvDiffHostRate), float32(dstHostSErrorRate), float32(dstHostSrvSErrorRate),
		float32(dstHostRErrorRate), float32(dstHostSrvRErrorRate))

	feature.SetHostFlowFeature(hostFlowFeature)

}

func (c *CountWindow) addInMap(tcpBaseFeature *flowFeature.TCPBaseFeature) {
	c.conversationQueue.Push(tcpBaseFeature)

	//sameHostMap
	dstIPStr := string(tcpBaseFeature.DstIP[:])
	c.sameHostMap[dstIPStr] = append(c.sameHostMap[dstIPStr], tcpBaseFeature)

	//sameHostServiceMap
	hostService := HostServiceKey{
		IP:      dstIPStr,
		Service: tcpBaseFeature.Service,
	}
	c.sameHostServiceMap[hostService] = append(c.sameHostServiceMap[hostService], tcpBaseFeature)

	//sameHostSrcPortMap
	hostSrcPort := HostSrcPortKey{
		IP:      dstIPStr,
		SrcPort: tcpBaseFeature.SrcPort,
	}
	c.sameHostSrcPortMap[hostSrcPort]++

	//sameSrcIPMap
	srcIPStr := string(tcpBaseFeature.SrcIP[:])
	c.sameSrcIPMap[srcIPStr]++
}
