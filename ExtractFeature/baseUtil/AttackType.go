package baseUtil

var AttackTypeMap = map[string]int{
	"normal":          0,
	"back":            1,  // dos
	"buffer_overflow": 2,  // u2r
	"ftp_write":       3,  // r2l
	"guess_passwd":    4,  // r2l
	"imap":            5,  // r2l
	"ipsweep":         6,  // probe
	"land":            7,  // dos
	"loadmodule":      8,  // u2r
	"multihop":        9,  // r2l
	"neptune":         10, // dos
	"nmap":            11, // probe
	"perl":            12, // u2r
	"phf":             13, // r2l
	"pod":             14, // dos
	"portsweep":       15, // probe
	"rootkit":         16, // u2r
	"satan":           17, // probe
	"smurf":           18, // dos
	"spy":             19, // r2l
	"teardrop":        20, // dos
	"warezclient":     21, // r2l
	"warezmaster":     22, // r2l
	"saint":           23,
	"mscan":           24,
	"apache2":         25,
	"snmpgetattack":   26,
	"processtable":    27,
	"httptunnel":      28,
	"ps":              29,
	"snmpguess":       30,
	"mailbomb":        31,
	"named":           32,
	"sendmail":        33,
	"xterm":           34,
	"worm":            35,
	"xlock":           36,
	"xsnoop":          37,
	"sqlattack":       38,
	"udpstorm":        39,
}

var AttackTypeList = []string{
	"normal",
	"back",  // dos
	"buffer_overflow",  // u2r
	"ftp_write",  // r2l
	"guess_passwd",  // r2l
	"imap",  // r2l
	"ipsweep",  // probe
	"land",  // dos
	"loadmodule",  // u2r
	"multihop",  // r2l
	"neptune", // dos
	"nmap", // probe
	"perl", // u2r
	"phf", // r2l
	"pod", // dos
	"portsweep", // probe
	"rootkit", // u2r
	"satan", // probe
	"smurf", // dos
	"spy", // r2l
	"teardrop", // dos
	"warezclient", // r2l
	"warezmaster", // r2l
	"saint",
	"mscan",
	"apache2",
	"snmpgetattack",
	"processtable",
	"httptunnel",
	"ps",
	"snmpguess",
	"mailbomb",
	"named",
	"sendmail",
	"xterm",
	"worm",
	"xlock",
	"xsnoop",
	"sqlattack",
	"udpstorm",
}