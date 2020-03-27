package flowFeature

import "strconv"

type TimeFlowFeature struct {
	Count           uint16		//23/41
	SrvCount        uint16		//24/41
	SErrorRate      float32		//25/41
	SrvSErrorRate   float32		//26/41
	RErrorRate      float32		//27/41
	SrvRErrorRate   float32		//28/41
	SameSrvRate     float32		//29/41  Dos Probe
	DiffSrvRate     float32		//30/41
	SrvDiffHostRate float32		//31/41
}

func (t TimeFlowFeature) FeatureToString() string {
	data := ""
	// data += strconv.Itoa(int(t.Count)) + ","
	// data += strconv.Itoa(int(t.SrvCount)) + ","
	// data += strconv.FormatFloat(float64(t.SErrorRate), 'f', 6, 64) + ","
	// data += strconv.FormatFloat(float64(t.SrvSErrorRate), 'f', 6, 64) + ","
	// data += strconv.FormatFloat(float64(t.RErrorRate), 'f', 6, 64) + ","
	// data += strconv.FormatFloat(float64(t.SrvRErrorRate), 'f', 6, 64) + ","
	data += strconv.FormatFloat(float64(t.SameSrvRate), 'f', 6, 64) + ","
	// data += strconv.FormatFloat(float64(t.DiffSrvRate), 'f', 6, 64) + ","
	// data += strconv.FormatFloat(float64(t.SrvDiffHostRate), 'f', 6, 64) + ","
	return data
}