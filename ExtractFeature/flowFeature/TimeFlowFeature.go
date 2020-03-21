package flowFeature

import "strconv"

type TimeFlowFeature struct {
	Count           uint16
	SrvCount        uint16
	SErrorRate      float32
	SrvSErrorRate   float32
	RErrorRate      float32
	SrvRErrorRate   float32
	SameSrvRate     float32
	DiffSrvRate     float32
	SrvDiffHostRate float32
}

func (t TimeFlowFeature) FeatureToString() string {
	data := ""
	data += strconv.Itoa(int(t.Count)) + ","
	data += strconv.Itoa(int(t.SrvCount)) + ","
	data += strconv.FormatFloat(float64(t.SErrorRate), 'f', 6, 64) + ","
	data += strconv.FormatFloat(float64(t.SrvSErrorRate), 'f', 6, 64) + ","
	data += strconv.FormatFloat(float64(t.RErrorRate), 'f', 6, 64) + ","
	data += strconv.FormatFloat(float64(t.SrvRErrorRate), 'f', 6, 64) + ","
	data += strconv.FormatFloat(float64(t.SameSrvRate), 'f', 6, 64) + ","
	data += strconv.FormatFloat(float64(t.DiffSrvRate), 'f', 6, 64) + ","
	data += strconv.FormatFloat(float64(t.SrvDiffHostRate), 'f', 6, 64) + ","
	return data
}
