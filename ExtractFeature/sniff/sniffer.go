package sniff

import (
	"FlowDetection/baseUtil"
	"FlowDetection/config"
	"FlowDetection/flowFeature"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const (
	snapshotLen uint32 = 1526
	timeout            = 30 * time.Second
)

//usage:
//	NewSniffer()
//	SetSnifferInterface(device string)
//	StartSniffer()
type Sniffer struct {
	Devices          []pcap.Interface
	handle           *pcap.Handle
	FragmentList     *ip4defrag.IPv4Defragmenter
	conversationPool *ConversationPool
	connMsg          map[uint16]*ConnMsg
}

func NewSniffer(featureChan chan *flowFeature.FlowFeature) (*Sniffer, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	return &Sniffer{
		Devices:          devices,
		FragmentList:     ip4defrag.NewIPv4Defragmenter(),
		conversationPool: NewConversationPool(featureChan),
		connMsg:          make(map[uint16]*ConnMsg),
	}, nil
}

//打印网卡详细信息
func (sniffer Sniffer) PrintDevices() {
	fmt.Print("Devices found")
	for _, device := range sniffer.Devices {
		fmt.Println("\nName", device.Name)
		fmt.Println("Description:", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- IP address:", address.IP)
			fmt.Println("- Subnet mask:", address.Netmask)
		}
	}
}

//设置嗅探网卡
func (sniffer *Sniffer) SetSnifferInterface(device string, promiscuous bool) error {
	handle, err := pcap.OpenLive(device, int32(snapshotLen), promiscuous, timeout)
	if err != nil {
		return err
	} else {
		sniffer.handle = handle
		return nil
	}

}

type ConnMsg struct {
	srcIP, dstIP [4]byte
	Start        time.Time
	Last         time.Time
	wrong        int
}

func (sniffer *Sniffer) StartSniffer() {
	defer sniffer.handle.Close()

	if !config.DEBUG {
		go sniffer.conversationPool.checkResultChan()

	}

	if baseUtil.CheckFileIsExist("test.pcap") {
		_ = os.Remove("test.pcap")
	}

	f, _ := os.Create("test.pcap")
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(snapshotLen, layers.LinkTypeEthernet)
	defer f.Close()

	packetCount := 0
	packetSource := gopacket.NewPacketSource(sniffer.handle, sniffer.handle.LinkType())
	packets := packetSource.Packets()

	i := 0
	//ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-packets:
			if i < 20 {
				log.Println("packget: ", i)
				i++
			}
			w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			sniffer.disposePacket(packet)
			//case <-ticker:
		}
		packetCount++
	}

	fmt.Println("end")
}

func (sniffer *Sniffer) disposePacket(packet gopacket.Packet) {
	ipv4 := packet.Layer(layers.LayerTypeIPv4)
	if ipv4 == nil {
		log.Println("(Sniffer.disposePacket) packet parsing fail!")
		log.Println(packet.LinkLayer().LayerType())
		return
	}

	ipv4Layer, ok := ipv4.(*layers.IPv4)
	if !ok {
		log.Println("cast failed!")
		return
	}

	//记录每个IP的时间，主要用于IP分片重组，记录第一个分片和最后一个分配到达时间
	//通过IP数据包中，每个分片的ID是唯一标识的
	t, ok := sniffer.connMsg[ipv4Layer.Id]
	if ok {
		t.Last = packet.Metadata().Timestamp
	} else {
		var srcIp, dstIp [4]byte
		copy(srcIp[:4], ipv4Layer.SrcIP)
		copy(dstIp[:4], ipv4Layer.DstIP)
		now := &ConnMsg{
			srcIP: srcIp,
			dstIP: dstIp,
			Start: packet.Metadata().Timestamp,
			Last:  packet.Metadata().Timestamp,
		}
		sniffer.connMsg[ipv4Layer.Id] = now
	}

	//对ip分片进行头部校验
	if !IPCheckSum(ipv4Layer.Contents[0:20]) {
		sniffer.connMsg[ipv4Layer.Id].wrong++
	}

	//检测是否需要ip分片重组
	ipPacket, err := sniffer.FragmentList.DefragIPv4WithTimestamp(
		ipv4Layer, packet.Metadata().Timestamp)
	if err != nil {
		log.Println("该包为IP分片！(sniffer.go 141)")
		return
	}

	payload := ipPacket.Payload

	switch ipPacket.Protocol {
	case layers.IPProtocolICMPv4:
		log.Println("icmp (sniffer.go 148)")
		p := gopacket.NewPacket(payload, layers.LayerTypeICMPv4, gopacket.Default)
		if layer := p.Layer(layers.LayerTypeICMPv4); layer != nil {
			if icmp, ok := layer.(*layers.ICMPv4); ok {
				sniffer.conversationPool.addICMPPacket(*icmp, *sniffer.connMsg[ipv4Layer.Id])
			}
		}
	case layers.IPProtocolTCP:
		log.Println("tcp (sniffer.go 156)")
		p := gopacket.NewPacket(payload, layers.LayerTypeTCP, gopacket.Default)
		if layer := p.Layer(layers.LayerTypeTCP); layer != nil {
			if tcp, ok := layer.(*layers.TCP); ok {
				sniffer.conversationPool.addTCPPacket(*tcp, *sniffer.connMsg[ipv4Layer.Id])
			}
		}

	case layers.IPProtocolUDP:
		log.Println("UDP (sniffer.go 165)")
		p := gopacket.NewPacket(payload, layers.LayerTypeUDP, gopacket.Default)
		if layer := p.Layer(layers.LayerTypeUDP); layer != nil {
			if udp := layer.(*layers.UDP); ok {
				sniffer.conversationPool.addUDPPacket(*udp, *sniffer.connMsg[ipv4Layer.Id])
			}
		}

	default:
		return
	}

	delete(sniffer.connMsg, ipv4Layer.Id)

}
