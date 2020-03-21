package flowFeature

import "strconv"

type TCPContentFeature struct {
	Host             uint8
	NumFailedLogins  uint8
	LoggedIn         uint8
	NumCompromised   uint
	RootShell        uint8
	SuAttempted      uint8
	NumRoot          uint
	NumFileCreations uint8
	NumShells        uint8
	NumAccessFiles   uint8
	NumOutboundCmds  uint
	IsHotLogin       uint8
	IsGuestLogin     uint8
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
