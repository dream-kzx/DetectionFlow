package flowFeature

import "strconv"

type HostFlowFeature struct {
	DstHostCount           uint16	//32/41
	DstHostSrvCount        uint16	//33/41 Probe
	DstHostSameSrvRate     float32	//34/41 Probe
	DstHostDiffSrvRate     float32	//35/41 Probe
	DstHostSameSrcPortRate float32	//36/41
	DstHostSrvDiffHostRate float32	//37/41
	DstHostSErrorRate      float32	//38/41
	DstHostSrvSErrorRate   float32	//39/41 Dos
	DstHostRErrorRate      float32	//40/41
	DstHostSrvRErrorRate   float32	//41/41
}

func (h HostFlowFeature) FeatureToString() string {
	data := ""
	// data += strconv.Itoa(int(h.DstHostCount)) + ","
	data += strconv.Itoa(int(h.DstHostSrvCount)) + ","
	data += strconv.FormatFloat(float64(h.DstHostSameSrvRate), 'f', 6, 64) + ","
	data += strconv.FormatFloat(float64(h.DstHostDiffSrvRate), 'f', 6, 64) + ","
	// data += strconv.FormatFloat(float64(h.DstHostSameSrcPortRate), 'f', 6, 64) + ","
	// data += strconv.FormatFloat(float64(h.DstHostSrvDiffHostRate), 'f', 6, 64) + ","
	// data += strconv.FormatFloat(float64(h.DstHostSErrorRate), 'f', 6, 64) + ","
	data += strconv.FormatFloat(float64(h.DstHostSrvSErrorRate), 'f', 6, 64) + ","
	// data += strconv.FormatFloat(float64(h.DstHostRErrorRate), 'f', 6, 64) + ","
	// data += strconv.FormatFloat(float64(h.DstHostSrvRErrorRate), 'f', 6, 64) + "\n"
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
