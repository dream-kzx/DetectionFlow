package flowFeature

import "strconv"

type TCPContentFeature struct {
	Host             uint8	//10/41
	NumFailedLogins  uint8	//11/41
	LoggedIn         uint8	//12/41
	NumCompromised   uint	//13/41
	RootShell        uint8	//14/41
	SuAttempted      uint8	//15/41
	NumRoot          uint	//16/41
	NumFileCreations uint8	//17/41
	NumShells        uint8	//18/41
	NumAccessFiles   uint8	//19/41
	NumOutboundCmds  uint	//20/41
	IsHotLogin       uint8	//21/41
	IsGuestLogin     uint8	//22//41
}

func (t TCPContentFeature) FeatureToString() string {
	data := ""
	data += strconv.Itoa(int(t.Host)) + ","
	data += strconv.Itoa(int(t.NumFailedLogins)) + ","
	data += strconv.Itoa(int(t.LoggedIn)) + ","
	data += strconv.Itoa(int(t.NumCompromised)) + ","
	data += strconv.Itoa(int(t.RootShell)) + ","
	data += strconv.Itoa(int(t.SuAttempted)) + ","
	data += strconv.Itoa(int(t.NumRoot)) + ","
	data += strconv.Itoa(int(t.NumFileCreations)) + ","
	data += strconv.Itoa(int(t.NumShells)) + ","
	data += strconv.Itoa(int(t.NumAccessFiles)) + ","
	data += strconv.Itoa(int(t.NumOutboundCmds)) + ","
	data += strconv.Itoa(int(t.IsHotLogin)) + ","
	data += strconv.Itoa(int(t.IsGuestLogin)) + ","
	return data
}
