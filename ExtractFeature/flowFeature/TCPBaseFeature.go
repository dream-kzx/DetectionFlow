package flowFeature

import (
	"FlowDetection/baseUtil"
	"github.com/google/gopacket/layers"
	"log"
	"strconv"
	"time"
)

const (
	ICMP = 1
	TCP  = 6
	UDP  = 17
)

type TCPBaseFeature struct {
	baseUtil.FiveTuple
	StartTime     time.Time
	LastTime      time.Time
	Duration      uint
	ProtocolType  string
	Service       uint8
	Flag          uint8
	SrcBytes      uint
	DstBytes      uint
	Land          uint8
	WrongFragment uint8
	Urgent        uint8
}

func (t TCPBaseFeature) Print() {
	log.Println("duration\tprotocol_type\tservice\tflag\tsrc_bytes\tdst_bytes" +
		"\tland\twrong_fragment\turgent")
	log.Printf("%d,%s,%d,%d,%d,%d,%d,%d,%d\n", t.Duration, t.ProtocolType,
		t.Service, t.Flag, t.SrcBytes, t.DstBytes, t.Land, t.WrongFragment, t.Urgent)
}

func (t TCPBaseFeature) IsSerror() bool {
	switch t.Flag {
	case baseUtil.S0, baseUtil.S1, baseUtil.S2, baseUtil.S3:
		return true
	default:
		return false
	}
}

func (t TCPBaseFeature) IsRerror() bool {
	if t.Flag == baseUtil.REJ {
		return true
	} else {
		return false
	}
}

func (t TCPBaseFeature) FeatureToString() string {
	data := ""
	data += strconv.Itoa(int(t.Duration)) + ","
	data += t.ProtocolType + ","
	data += ServiceToString(t.Service) + ","
	data += FlagToString(t.Flag) + ","
	data += strconv.Itoa(int(t.SrcBytes)) + ","
	data += strconv.Itoa(int(t.DstBytes)) + ","
	data += strconv.Itoa(int(t.Land)) + ","
	data += strconv.Itoa(int(t.WrongFragment)) + ","
	data += strconv.Itoa(int(t.Urgent)) + ","

	return data
}

func ServiceToString(service uint8) string {
	switch service {
	case baseUtil.SRV_OTHER:
		return "other"
	case baseUtil.SRV_PRIVATE:
		return "private"
	case baseUtil.SRV_ECR_I:
		return "ecr_i"
	case baseUtil.SRV_URP_I:
		return "urp_i"
	case baseUtil.SRV_URH_I:
		return "urh_i"
	case baseUtil.SRV_RED_I:
		return "red_i"
	case baseUtil.SRV_ECO_I:
		return "eco_I"
	case baseUtil.SRV_TIM_I:
		return "tim_i"
	case baseUtil.SRV_OTH_I:
		return "oth_i" /////
	case baseUtil.SRV_DOMAIN_U:
		return "domain_u"
	case baseUtil.SRV_TFTP_U:
		return "tftp_u"
	case baseUtil.SRV_NTP_U:
		return "ntp_u"
	case baseUtil.SRV_IRC:
		return "IRC"
	case baseUtil.SRV_X11:
		return "X11"
	case baseUtil.SRV_Z39_50:
		return "Z39_50"
	case baseUtil.SRV_AOL:
		return "aol"
	case baseUtil.SRV_AUTH:
		return "auth"
	case baseUtil.SRV_BGP:
		return "bgp"
	case baseUtil.SRV_COURIER:
		return "courier"
	case baseUtil.SRV_CSNET_NS:
		return "csnet_ns"
	case baseUtil.SRV_CTF:
		return "ctf"
	case baseUtil.SRV_DAYTIME:
		return "daytime"
	case baseUtil.SRV_DISCARD:
		return "discard"
	case baseUtil.SRV_DOMAIN:
		return "domain"
	case baseUtil.SRV_ECHO:
		return "echo"
	case baseUtil.SRV_EFS:
		return "efs"
	case baseUtil.SRV_EXEC:
		return "exec"
	case baseUtil.SRV_FINGER:
		return "finger"
	case baseUtil.SRV_FTP:
		return "ftp"
	case baseUtil.SRV_FTP_DATA:
		return "ftp_data"
	case baseUtil.SRV_GOPHER:
		return "gopher"
	case baseUtil.SRV_HARVEST:
		return "harvest"
	case baseUtil.SRV_HOSTNAMES:
		return "hostnames"
	case baseUtil.SRV_HTTP:
		return "http"
	case baseUtil.SRV_HTTP_2784:
		return "http_2784"
	case baseUtil.SRV_HTTP_443:
		return "http_443"
	case baseUtil.SRV_HTTP_8001:
		return "http_8001"
	case baseUtil.SRV_ICMPD:
		return "icmpd" ///
	case baseUtil.SRV_IMAP4:
		return "imap4"
	case baseUtil.SRV_ISO_TSAP:
		return "iso_tsap"
	case baseUtil.SRV_KLOGIN:
		return "klogin"
	case baseUtil.SRV_KSHELL:
		return "kshell"
	case baseUtil.SRV_LDAP:
		return "ldap"
	case baseUtil.SRV_LINK:
		return "link"
	case baseUtil.SRV_LOGIN:
		return "login"
	case baseUtil.SRV_MTP:
		return "mtp"
	case baseUtil.SRV_NAME:
		return "name"
	case baseUtil.SRV_NETBIOS_DGM:
		return "netbios_dgm"
	case baseUtil.SRV_NETBIOS_NS:
		return "netbios_ns"
	case baseUtil.SRV_NETBIOS_SSN:
		return "netbios_ssn"
	case baseUtil.SRV_NETSTAT:
		return "netstat"
	case baseUtil.SRV_NNSP:
		return "nnsp"
	case baseUtil.SRV_NNTP:
		return "nntp"
	case baseUtil.SRV_PM_DUMP:
		return "pm_dump"
	case baseUtil.SRV_POP_2:
		return "pop_2"
	case baseUtil.SRV_POP_3:
		return "pop_3"
	case baseUtil.SRV_PRINTER:
		return "printer"
	case baseUtil.SRV_REMOTE_JOB:
		return "remote_job"
	case baseUtil.SRV_RJE:
		return "rje"
	case baseUtil.SRV_SHELL:
		return "shell"
	case baseUtil.SRV_SMTP:
		return "smtp"
	case baseUtil.SRV_SQL_NET:
		return "sql_net"
	case baseUtil.SRV_SSH:
		return "ssh"
	case baseUtil.SRV_SUNRPC:
		return "sunrpc"
	case baseUtil.SRV_SUPDUP:
		return "supdup"
	case baseUtil.SRV_SYSTAT:
		return "systat"
	case baseUtil.SRV_TELNET:
		return "telnet"
	case baseUtil.SRV_TIME:
		return "time"
	case baseUtil.SRV_UUCP:
		return "uucp"
	case baseUtil.SRV_UUCP_PATH:
		return "uucp_path"
	case baseUtil.SRV_VMNET:
		return "vmnet"
	case baseUtil.SRV_WHOIS:
		return "whois"
	default:
		return ""
		//NUMBER_OF_SERVICES"
	}
}

func FlagToString(flag uint8) string {
	switch flag {
	case baseUtil.SF:
		return "SF"
	case baseUtil.S0:
		return "S0"
	case baseUtil.S1:
		return "S1"
	case baseUtil.S2:
		return "S2"
	case baseUtil.S3:
		return "S3"
	case baseUtil.REJ:
		return "REJ"
	case baseUtil.RSTOS0:
		return "RSTOS0"
	case baseUtil.RSTO:
		return "RSTO"
	case baseUtil.RSTR:
		return "RSTR"
	case baseUtil.SH:
		return "SH"
	case baseUtil.OTH:
		return "OTH"
	default:
		return ""
	}
}

func NewTcpBaseFeature(fiveTuple baseUtil.FiveTuple, duration uint, protocolType layers.IPProtocol,
	service, flag, srcBytes, dstBytes, land, wrongFragment, urgent int) *TCPBaseFeature {

	var proType string

	switch protocolType {
	case layers.IPProtocolICMPv4:
		proType = "icmp"
	case layers.IPProtocolTCP:
		proType = "tcp"
	case layers.IPProtocolUDP:
		proType = "udp"
	default:
		proType = ""
	}

	return &TCPBaseFeature{
		FiveTuple:     fiveTuple,
		Duration:      duration,
		ProtocolType:  proType,
		Service:       uint8(service),
		Flag:          uint8(flag),
		SrcBytes:      uint(srcBytes),
		DstBytes:      uint(dstBytes),
		Land:          uint8(land),
		WrongFragment: uint8(wrongFragment),
		Urgent:        uint8(urgent),
	}
}
