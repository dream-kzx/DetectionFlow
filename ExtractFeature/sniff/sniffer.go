package sniff

import (
	"FlowDetection/GUI"
	"FlowDetection/baseUtil"
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
	timeout            = 1 * time.Second
)

var (
	BlackToSnifferChan chan *GUI.OperateSniffer
	BlackList          map[string]interface{}
	WriteFile          *bool
	wPcap              *pcapgo.Writer
)

func init() {
	BlackList = make(map[string]interface{},100)
}

func receiveBlack() {
	for {
		select {
		case black, ok := <-BlackToSnifferChan:
			if !ok {
				log.Fatal("黑名单接收信道出现问题")
			}

			_, ok = BlackList[black.IP]
			if !ok && black.Operate == 1 {
				BlackList[black.IP] = struct{}{}
			} else if ok && black.Operate == 0 {
				delete(BlackList, black.IP)
			}
		}
	}
}

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

func (sniffer *Sniffer) StartSniffer(blackToSnifferChan chan *GUI.OperateSniffer, writeFile *bool) {
	defer sniffer.handle.Close()

	go receiveBlack()
	go sniffer.conversationPool.checkResultChan()

	BlackToSnifferChan = blackToSnifferChan
	WriteFile = writeFile

	//写PCAP文件
	if *WriteFile {
		if baseUtil.CheckFileIsExist("test.pcap") {
			_ = os.Remove("test.pcap")
		}
		f, _ := os.Create("test.pcap")
		wPcap = pcapgo.NewWriter(f)
		_ = wPcap.WriteFileHeader(snapshotLen, layers.LinkTypeEthernet)
		defer f.Close()
	}

	packetSource := gopacket.NewPacketSource(sniffer.handle, sniffer.handle.LinkType())
	packets := packetSource.Packets()

	for {
		select {
		case packet := <-packets:
			//写PCAP文件
			if *WriteFile {
				err := wPcap.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
				if err != nil {
					log.Println(err)
				}
			}

			sniffer.conversationPool.DisposePacket(packet)
		case <-time.After(2 * time.Second):
			log.Println("2秒内没有连接到达...(sniffer.go 112)")
			sniffer.conversationPool.checkTimeout(time.Now())

		}

	}

}
