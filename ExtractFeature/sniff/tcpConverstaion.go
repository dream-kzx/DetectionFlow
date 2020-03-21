package sniff

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"learn/baseUtil"
	"learn/config"
	"learn/flowFeature"
	"time"
)

type TCPConversation struct {
	gopacket.Flow
	Conversation
	tcpNum   int
	poolChan chan interface{} //用于结束后返回结果到pool
	timeout  *time.Ticker     //timeout
	back     bool             //用于在超时之后，是否返回结果
}

func (t *TCPConversation) addPacket(tcp layers.TCP, msg ConnMsg) *TCPConversation {
	//在有新的包到来时，重新计时
	t.back = false
	if t.timeout != nil {
		t.timeout.Stop()
	}

	fiveTuple := baseUtil.FiveTuple{
		SrcIP:        t.SrcIP,
		DstIP:        t.DstIP,
		SrcPort:      t.SrcPort,
		DstPort:      t.DstPort,
		ProtocolType: t.ProtocolType,
	}

	//连接请求syn=1，ack=0
	if tcp.SYN && !tcp.ACK {
		if t.Flag == 0 { //如果是新创建的连接
			//记录TCP连接的Flag状态
			t.Flag = baseUtil.INIT
			//记录TCP连接land状态
			if msg.srcIP == msg.dstIP {
				t.Land = 1
			} else {
				t.Land = 0
			}

			//记录TCP连接的Service
			t.Service = GetTCPServiceType(fiveTuple)
		} else { //如果是旧的连接则，

			//提取特征,并加入结果信道
			t.extractBaseFeature()

			//创建新的连接，并返回
			newTCPConversation := NewTCPConversation(fiveTuple, msg.Start,
				tcp.TransportFlow(), t.poolChan)

			newTCPConversation.Flag = baseUtil.INIT
			if msg.srcIP == msg.dstIP {
				newTCPConversation.Land = 1
			} else {
				newTCPConversation.Land = 0
			}

			//记录TCP连接的Service
			newTCPConversation.Service = GetTCPServiceType(fiveTuple)
			return newTCPConversation
		}

	} else {
		if t.Flag == 0 { //如果是新的连接
			//记录TCP连接的Flag状态
			t.Flag = baseUtil.INIT
			//记录TCP连接的Service
			t.Service = GetTCPServiceType(fiveTuple)
			//记录TCP连接land状态
			if msg.srcIP == msg.dstIP {
				t.Land = 1
			} else {
				t.Land = 0
			}
		}

		//如果为客户机发来的包，记录srcBytes，dstBytes
		if t.DstIP == config.SERVERIP {
			t.SrcBytes += len(tcp.Payload)
		} else {
			t.DstBytes += len(tcp.Payload)
		}

		//判断是否是加急包
		if tcp.URG {
			t.Urgent++
		}

		//获取这个包的接收时间
		t.LastTime = msg.Last

		//激活错误分片数
		t.WrongFragment += msg.wrong

		//更新tcp连接状态
		t.updateState(tcp, msg.srcIP)

		if t.isFinal() {
			//提取特征
			t.extractBaseFeature()

			return nil
		}

	}

	t.back = true

	go t.checkTimeout() ///////////////////////////////////////////////

	return nil
}

//提取特征，传入返回结果信道
func (t *TCPConversation) extractBaseFeature() {
	duration := uint(t.LastTime.Sub(t.StartTime))

	tcpFeature := flowFeature.NewTcpBaseFeature(t.FiveTuple, duration, t.FiveTuple.ProtocolType,
		t.Service, t.Flag, t.SrcBytes, t.DstBytes, t.Land, t.WrongFragment, t.Urgent)
	tcpFeature.StartTime = t.StartTime
	tcpFeature.LastTime = t.LastTime
	resultChan := NewResultChan(t.FiveTuple.FastHash(), tcpFeature)
	t.poolChan <- resultChan
}

//检测连接是否超时
func (t *TCPConversation) checkTimeout() {
	t.timeout = time.NewTicker(time.Second * 2)
	select {
	case <-t.timeout.C:
		if t.back {
			//提取特征返回
			t.extractBaseFeature()
		}
	}
}

//更新连接的状态
func (t *TCPConversation) updateState(tcp layers.TCP, srcIP [4]byte) {
	nowState := t.Flag

	from := config.SERVERIP != srcIP //判断是否是客户机发来的包

	switch nowState {
	case baseUtil.INIT:
		if tcp.SYN && !tcp.ACK && from {
			t.Flag = baseUtil.S0
		} else {
			t.Flag = baseUtil.OTH
		}
	case baseUtil.S0:
		if tcp.RST && !from {
			t.Flag = baseUtil.REJ
		} else if tcp.RST && from {
			t.Flag = baseUtil.RSTOS0
		} else if tcp.FIN && from {
			t.Flag = baseUtil.SH
		} else if tcp.SYN && tcp.ACK && !from {
			t.Flag = baseUtil.S1
		}
	case baseUtil.S1:
		if tcp.ACK && from {
			t.Flag = baseUtil.ESTAB
		} else if tcp.RST && from {
			t.Flag = baseUtil.RSTO
		} else if tcp.RST && !from {
			t.Flag = baseUtil.RSTR
		}
	case baseUtil.ESTAB:
		if tcp.FIN && from {
			t.Flag = baseUtil.S2
		} else if tcp.FIN && !from {
			t.Flag = baseUtil.S3
		} else if tcp.RST && from {
			t.Flag = baseUtil.RSTO
		} else if tcp.RST && !from {
			t.Flag = baseUtil.RSTR
		}
	case baseUtil.S2:
		if tcp.FIN && !from {
			t.Flag = baseUtil.S2F
		} else if tcp.RST && from {
			t.Flag = baseUtil.RSTO
		} else if tcp.RST && !from {
			t.Flag = baseUtil.RSTR
		}
	case baseUtil.S3:
		if tcp.FIN && from {
			t.Flag = baseUtil.S3F
		} else if tcp.RST && from {
			t.Flag = baseUtil.RSTO
		} else if tcp.RST && !from {
			t.Flag = baseUtil.RSTR
		}
	case baseUtil.S2F:
		if tcp.ACK && from {
			t.Flag = baseUtil.SF
		} else if tcp.RST && from {
			t.Flag = baseUtil.RSTO
		} else if tcp.RST && !from {
			t.Flag = baseUtil.RSTR
		}
	case baseUtil.S3F:
		if tcp.ACK && !from {
			t.Flag = baseUtil.SF
		} else if tcp.RST && from {
			t.Flag = baseUtil.RSTO
		} else if tcp.RST && !from {
			t.Flag = baseUtil.RSTR
		}
	}
}

//判断连接是否结束
func (t *TCPConversation) isFinal() bool {
	//switch t.Flag {
	//case INIT,S0,S1,ESTAB,S2,S3:
	//	return false
	//case REJ, RSTR,RSTO,RSTOS0:
	//	return false
	//default:
	//	return true
	//}

	switch t.Flag {
	case baseUtil.SF:
		return true
	case baseUtil.REJ, baseUtil.RSTO, baseUtil.RSTR, baseUtil.RSTOS0:
		return true
	default:
		return false
	}

}

func NewTCPConversation(tuple baseUtil.FiveTuple, start time.Time, flow gopacket.Flow,
	poolChan chan interface{}) *TCPConversation {
	return &TCPConversation{
		Conversation: Conversation{
			FiveTuple: tuple,
			StartTime: start,
		},
		Flow:     flow,
		poolChan: poolChan,
	}
}
