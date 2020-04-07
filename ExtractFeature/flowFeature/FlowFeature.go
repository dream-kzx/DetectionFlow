package flowFeature

type FlowFeature struct {
	TCPBaseFeature
	//TCP连接基本特征（共9种）
	//Duration      float64
	//ProtocolType  string
	//Service       uint8
	//Flag          uint8
	//SrcBytes      uint
	//DstBytes      uint
	//Land          uint8
	//WrongFragment uint8
	//Urgent        uint8

	TCPContentFeature
	// TCP连接的内容特征（共13种） TCPContentFeature
	//Host             uint8
	//NumFailedLogins  uint8
	//LoggedIn         uint8
	//NumCompromised   uint
	//RootShell        uint8
	//SuAttempted      uint8
	//NumRoot          uint
	//NumFileCreations uint8
	//NumShells        uint8
	//NumAccessFiles   uint8
	//NumOutboundCmds  uint
	//IsHotLogin       uint8
	//IsGuestLogin     uint8

	TimeFlowFeature
	//基于时间的网络流量统计特征 （共9种，23～31）TimeFlowFeature
	//Count uint16
	//SrvCount uint16
	//SErrorRate float32
	//SrvSErrorRate float32
	//RErrorRate float32
	//SrvRErrorRate float32
	//SameSrvRate float32
	//DiffSrvRate float32
	//SrvDiffHostRate float32

	HostFlowFeature
	//基于主机的网络流量统计特征 （共10种，32～41）HostFlowFeature
	//DstHostCount           uint16
	//DstHostSrvCount        uint16
	//DstHostSameSrvRate     float32
	//DstHostDiffSrvRate     float32
	//DstHostSameSrcPortRate float32
	//DstHostSrvDiffHostRate float32
	//DstHostSErrorRate      float32
	//DstHostSrvSErrorRate   float32
	//DstHostRErrorRate      float32
	//DstHostSrvRErrorRate   float32
}

func (f *FlowFeature) FeatureToString() string {
	data := ""
	data += f.TCPBaseFeature.FeatureToString()
	data += f.TCPContentFeature.FeatureToString()
	data += f.TimeFlowFeature.FeatureToString()
	data += f.HostFlowFeature.FeatureToString()
	return data
}

func (f *FlowFeature) SetTCPBaseFeature(tcpBaseFeature *TCPBaseFeature) {
	f.TCPBaseFeature = *tcpBaseFeature
}

func (f *FlowFeature) SetTCPContentFeature(contentFeature *TCPContentFeature) {
	f.TCPContentFeature = *contentFeature
}

func (f *FlowFeature) SetTimeFlowFeature(timeFlowFeature *TimeFlowFeature) {
	f.TimeFlowFeature = *timeFlowFeature
}

func (f *FlowFeature) SetHostFlowFeature(hostFlowFeature *HostFlowFeature) {
	f.HostFlowFeature = *hostFlowFeature
}

func NewFlowFeature() *FlowFeature {
	return &FlowFeature{}
}