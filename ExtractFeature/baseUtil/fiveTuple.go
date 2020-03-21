package baseUtil

import (
	"github.com/google/gopacket/layers"
)

const fnvBasis = 14695981039346656037
const fnvPrime = 1099511628211

type FiveTuple struct {
	SrcIP, DstIP     [4]byte
	SrcPort, DstPort uint16
	ProtocolType     layers.IPProtocol
}

func (f *FiveTuple) FastHash() (h uint64) {
	var data []byte
	data = append(data, uint16ToBytes(f.DstPort)...)
	data = append(data, uint16ToBytes(f.SrcPort)...)
	for _, n := range f.SrcIP {
		data = append(data, n)
	}

	for _, n := range f.DstIP {
		data = append(data, n)
	}

	h = fnvHash(data)
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
