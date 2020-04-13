package baseUtil

import (
	"github.com/google/gopacket/layers"
	"strconv"
)

const fnvBasis = 14695981039346656037
const fnvPrime = 1099511628211

type FiveTuple struct {
	SrcIP, DstIP     [4]byte
	SrcPort, DstPort uint16
	ProtocolType     layers.IPProtocol
}

func (f *FiveTuple) FastHash() (h uint64) {
	data1 := uint16ToBytes(f.DstPort)
	data2 := uint16ToBytes(f.SrcPort)
	h = fnvHash(data1) + fnvHash(data2) + fnvHash(f.SrcIP[:]) + fnvHash(f.DstIP[:])
	h ^= uint64(f.ProtocolType)
	h *= fnvPrime

	return
}

func fnvHash(s []byte) (h uint64) {
	h = fnvBasis
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= fnvPrime
	}
	return
}

func uint16ToBytes(num uint16) []byte {
	result := make([]byte, 0)
	result = append(result, byte(num>>8))
	result = append(result, byte(num&0xFF))
	return result
}


func IpToString(ip [4]byte) string {
	data := ""
	data += strconv.Itoa(int(ip[0])) + "."
	data += strconv.Itoa(int(ip[1])) + "."
	data += strconv.Itoa(int(ip[2])) + "."
	data += strconv.Itoa(int(ip[3]))
	return data
}