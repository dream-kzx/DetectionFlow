package flowFeature

import "strconv"

type HostFlowFeature struct {
	DstHostCount           uint16
	DstHostSrvCount        uint16
	DstHostSameSrvRate     float32
	DstHostDiffSrvRate     float32
	DstHostSameSrcPortRate float32
	DstHostSrvDiffHostRate float32
	DstHostSErrorRate      float32
	DstHostSrvSErrorRate   float32
	DstHostRErrorRate      float32
	DstHostSrvRErrorRate   float32
}

func (h HostFlowFeature) FeatureToString() string {
	data := ""
	data += strconv.Itoa(int(h.DstHostCount)) + ","
	data += strconv.Itoa(int(h.DstHostSrvCount)) + ","
	data += strconv.FormatFloat(float64(h.DstHostSameSrvRate), 'f', 6, 64) + ","
	data += strconv.FormatFloat(float64(h.DstHostDiffSrvRate), 'f', 6, 64) + ","
	data += strconv.FormatFloat(float64(h.DstHostSameSrcPortRate), 'f', 6, 64) + ","
	data += strconv.FormatFloat(float64(h.DstHostSrvDiffHostRate), 'f', 6, 64) + ","
	data += strconv.FormatFloat(float64(h.DstHostSErrorRate), 'f', 6, 64) + ","
	data += strconv.FormatFloat(float64(h.DstHostSrvSErrorRate), 'f', 6, 64) + ","
	data += strconv.FormatFloat(float64(h.DstHostRErrorRate), 'f', 6, 64) + ","
	data += strconv.FormatFloat(float64(h.DstHostSrvRErrorRate), 'f', 6, 64) + "\n"
	return data
}

func NewHostFlowFeature(dstHostCount, dstHostSrvCount uint16, dstHostSameSrvRate,
	dstHostDiffSrvRate, dstHostSameSrcPortRate, dstHostSrvDiffHostRate,
	dstHostSErrorRate, dstHostSrvSErrorRate, DstHostRErrorRate,
	dstHostSrvRErrorRate float32) *HostFlowFeature {
	return &HostFlowFeature{
		DstHostCount:           dstHostCount,
		DstHostSrvCount:        dstHostSrvCount,
		DstHostSameSrvRate:     dstHostSameSrvRate,
		DstHostDiffSrvRate:     dstHostDiffSrvRate,
		DstHostSameSrcPortRate: dstHostSameSrcPortRate,
		DstHostSrvDiffHostRate: dstHostSrvDiffHostRate,
		DstHostSErrorRate:      dstHostSErrorRate,
		DstHostSrvSErrorRate:   dstHostSrvSErrorRate,
		DstHostRErrorRate:      DstHostRErrorRate,
		DstHostSrvRErrorRate:   dstHostSrvRErrorRate,
	}

}
