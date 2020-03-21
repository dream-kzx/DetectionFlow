package sniff

import (
	"learn/flowFeature"
	"time"
)

type MapValue struct {
	Count       uint
	SErrorCount uint
	RErrorCount uint
}

//在2秒内的连接特征窗口
type TimeWindow struct {
	conversationQueue  *Queue
	sameHostMap        map[string]*MapValue
	sameServiceMap     map[uint8]*MapValue
	sameHostServiceMap map[HostServiceKey]uint
}

func NewTimeWindow() *TimeWindow {
	return &TimeWindow{
		conversationQueue: NewQueue(),
		//相同主机Map，包含了相同主机连接的个数、syn的错误的个数，rej错误的个数
		sameHostMap: make(map[string]*MapValue),
		//相同服务Map，包含了相同服务连接的个数、syn的错误的个数，rej错误的个数
		sameServiceMap: make(map[uint8]*MapValue),
		//相同主机相同服务的连接的个数
		sameHostServiceMap: make(map[HostServiceKey]uint),
	}
}

//向窗口加入一个连接
func (t *TimeWindow) AddConversation(
	tcpBaseFeature *flowFeature.TCPBaseFeature, feature *flowFeature.FlowFeature) {

	t.removeInMap(tcpBaseFeature.LastTime)
	t.calculateFeature(tcpBaseFeature, feature)
	t.addInMap(tcpBaseFeature)

}

//移除窗口中大于2秒的连接
func (t *TimeWindow) removeInMap(lastTime time.Time) {
	earliestTime := lastTime.Add(-2 * time.Second)
	conversationList := t.conversationQueue.List()

	for _, conversation := range conversationList {
		if earliestTime.Sub(conversation.LastTime) <= 0 {
			break
		}

		//从队列中移除连接
		con := t.conversationQueue.Front()
		t.conversationQueue.Pop()

		dstIPStr := string(con.DstIP[:])
		service := con.Service

		sameHost := t.sameHostMap[dstIPStr]
		sameService := t.sameServiceMap[service]

		sameHost.Count--
		sameService.Count--

		//移除map中syn错误的计数
		if con.IsSerror() {
			sameHost.SErrorCount--
			sameService.SErrorCount--
		}
		//移除map中rej错误的计数
		if con.IsRerror() {
			sameHost.RErrorCount--
			sameService.RErrorCount--
		}

		if sameHost.Count == 0 {
			delete(t.sameHostMap, dstIPStr)
		}

		if sameService.Count == 0 {
			delete(t.sameServiceMap, service)
		}

		hostService := HostServiceKey{
			IP:      dstIPStr,
			Service: service,
		}

		t.sameHostServiceMap[hostService]--

		if t.sameHostServiceMap[hostService] == 0 {
			delete(t.sameHostServiceMap, hostService)
		}

	}

}

//提取特征
func (t *TimeWindow) calculateFeature(tcpBaseFeature *flowFeature.TCPBaseFeature,
	feature *flowFeature.FlowFeature) {

	dstIPStr := string(tcpBaseFeature.DstIP[:])
	service := tcpBaseFeature.Service
	hostService := HostServiceKey{
		IP:      dstIPStr,
		Service: service,
	}

	count := uint(0)
	hostSErrorCount := uint(0)
	hostRErrorCount := uint(0)
	sameHost, ok := t.sameHostMap[dstIPStr]
	if ok {
		count = sameHost.Count
		hostSErrorCount = sameHost.SErrorCount
		hostRErrorCount = sameHost.RErrorCount
	}

	srvCount := uint(0)
	srvSErrorCount := uint(0)
	srvRErrorCount := uint(0)
	sameService := t.sameServiceMap[service]
	if ok {
		srvCount = sameService.Count
		srvSErrorCount = sameService.SErrorCount
		srvRErrorCount = sameService.RErrorCount
	}

	sameHostService, ok := t.sameHostServiceMap[hostService]
	if !ok {
		sameHostService = 0
	}

	serrorRate := 0.0
	rerrorRate := 0.0
	sameSrvRate := 0.0
	if count != 0 {
		serrorRate = float64(hostSErrorCount) / float64(count)
		rerrorRate = float64(hostRErrorCount) / float64(count)
		sameSrvRate = float64(sameHostService) / float64(count)
	}

	diffSrvRate := 1 - sameSrvRate
	srvSErrorRate := 0.0
	srvRErrorRate := 0.0
	srvDiffHostRate := 0.0
	if srvCount != 0 {
		srvSErrorRate = float64(srvSErrorCount) / float64(srvCount)
		srvRErrorRate = float64(srvRErrorCount) / float64(srvCount)
		srvDiffHostRate = 1 - (float64(sameHostService) / float64(srvCount))
	}

	timeFeature := &flowFeature.TimeFlowFeature{
		Count:           uint16(count),
		SrvCount:        uint16(srvCount),
		SErrorRate:      float32(serrorRate),
		SrvSErrorRate:   float32(srvSErrorRate),
		RErrorRate:      float32(rerrorRate),
		SrvRErrorRate:   float32(srvRErrorRate),
		SameSrvRate:     float32(sameSrvRate),
		DiffSrvRate:     float32(diffSrvRate),
		SrvDiffHostRate: float32(srvDiffHostRate),
	}

	feature.SetTimeFlowFeature(timeFeature)

}

//将新连接加入窗口
func (t *TimeWindow) addInMap(
	tcpBaseFeature *flowFeature.TCPBaseFeature) {
	dstIPStr := string(tcpBaseFeature.DstIP[:])

	t.conversationQueue.Push(tcpBaseFeature)

	synError := uint(0)
	if tcpBaseFeature.IsSerror() {
		synError = 1
	}

	rejError := uint(0)
	if tcpBaseFeature.IsRerror() {
		rejError = 1
	}

	sameHost, ok := t.sameHostMap[dstIPStr]
	if !ok {
		sameHost = &MapValue{
			Count:       0,
			SErrorCount: 0,
			RErrorCount: 0,
		}
		t.sameHostMap[dstIPStr] = sameHost
	}

	sameHost.Count++
	sameHost.SErrorCount += synError
	sameHost.RErrorCount += rejError

	sameService, ok := t.sameServiceMap[tcpBaseFeature.Service]
	if !ok {
		sameService = &MapValue{
			Count:       0,
			SErrorCount: 0,
			RErrorCount: 0,
		}
		t.sameServiceMap[tcpBaseFeature.Service] = sameService
	}

	sameService.Count++
	sameService.SErrorCount += synError
	sameService.RErrorCount += rejError

	hostservice := HostServiceKey{
		IP:      dstIPStr,
		Service: tcpBaseFeature.Service,
	}
	t.sameHostServiceMap[hostservice]++

}
