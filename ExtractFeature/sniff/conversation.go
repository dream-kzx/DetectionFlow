package sniff

import (
	"FlowDetection/baseUtil"
	"FlowDetection/config"
	"log"
	"time"
)

func IPCheckSum(data []byte) bool {
	var sum uint32

	for i := 0; i < 20; i += 2 {
		sum += uint32(data[i]) << 8
		sum += uint32(data[i+1])
	}

	sum1 := uint16(sum >> 16)
	sum2 := uint16(sum & 0xFFFF)

	result := sum1 + sum2

	if ^result == 0 {
		return true
	}
	return false
}

type Conversation struct {
	baseUtil.FiveTuple
	StartTime     time.Time //+
	LastTime      time.Time //+
	Service       int
	Flag          int //连接正常或错误的状态
	SrcBytes      int //从源主机到目标主机的数据的字节数+
	DstBytes      int //从目标主机到源主机的数据的字节数+
	Land          int //若连接来自/送达同一个主机/端口则为1，否则为0，离散类型，0或1+
	WrongFragment int //错误分段的数量，连续类型，范围是 [0, 3]。+
	Urgent        int //加急包的个数，连续类型，范围是[0, 14]。+
}

func GetTCPServiceType(fiveTuple baseUtil.FiveTuple) int {
	srcPort := uint16(0)
	dstPort := uint16(0)
	if fiveTuple.DstIP == config.SERVERIP {
		srcPort = fiveTuple.SrcPort
		dstPort = fiveTuple.DstPort
	} else {
		srcPort = fiveTuple.DstPort
		dstPort = fiveTuple.SrcPort
	}

	if srcPort == 20 {
		return baseUtil.SRV_FTP_DATA
	}

	switch dstPort {
	case 194, 529, 2218, 6665, 6666, 6668, 6669, 6697: // Internet Relay Chat via TLS/SSL
		return baseUtil.SRV_IRC

	case 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009, 6010, 6011, 6012, 6013, 6014, 6015, 6016,
		6017, 6018, 6019, 6020, 6021, 6022, 6023, 6024, 6025, 6026, 6027, 6028, 6029, 6030, 6031, 6032, 6033, 6034,
		6035, 6036, 6037, 6038, 6039, 6040, 6041, 6042, 6043, 6044, 6045, 6046, 6047, 6048, 6049, 6050, 6051, 6052,
		6053, 6054, 6055, 6056, 6057, 6058, 6059, 6060, 6061, 6062, 6063:
		return baseUtil.SRV_X11

	case 210: // ANSI Z39.50
		return baseUtil.SRV_Z39_50

	case 5190, 5191, 5192, 5193, 531: // AOL Instant Messenger
		return baseUtil.SRV_AOL
	case 113, 31, 56, 222, 353, 370, 1615, 2139, 2147, 2334, 2392, 2478, 2821, 3113, 3207, 3710,
		3799, 3810, 3833, 3871, 4032, 4129, 4373, 5067, 5635, 6268, 6269, 7004, 7847, 9002, 19194, 27999:
		return baseUtil.SRV_AUTH

	case 179: // Border Gateway Protocol
		return baseUtil.SRV_BGP

	case 530, 165: // Xerox (xns-courier)
		return baseUtil.SRV_COURIER
	case 105: // Mailbox Name Nameserver
		return baseUtil.SRV_CSNET_NS

	case 84: // Common Trace Facility
		return baseUtil.SRV_CTF

	case 13: // Daytime
		return baseUtil.SRV_DAYTIME

	case 9: // Discard
		return baseUtil.SRV_DISCARD
	case 53: // Domain Name Server
		return baseUtil.SRV_DOMAIN

	case 7: //
		return baseUtil.SRV_ECHO
	case 520: // extended file name server
		return baseUtil.SRV_EFS
	case 512: // remote process execution; authentication performed using passwords and UNIX login names
		return baseUtil.SRV_EXEC

	case 79: // Finger
		return baseUtil.SRV_FINGER

	case 21: // File Transfer Protocol [Control]
		return baseUtil.SRV_FTP

	case 20: // File Transfer [Default Data] (TODO)
		return baseUtil.SRV_FTP_DATA

	case 70: // Gopher
		return baseUtil.SRV_GOPHER

	// TODO: service harvest port number
	//case: //
	//	return SRV_HARVEST;
	//	break;

	case 101: // NIC Host Name Server
		return baseUtil.SRV_HOSTNAMES

	case 80, 8008, 8080: // HTTP Alternate
		return baseUtil.SRV_HTTP

	case 2784: // world wide web - development (www-dev)
		return baseUtil.SRV_HTTP_2784

	case 443: // http protocol over TLS/SSL
		return baseUtil.SRV_HTTP_443

	case 8001: // VCOM Tunnel(iana) / Commonly used for Internet radio streams such as SHOUTcast (wiki)
		return baseUtil.SRV_HTTP_8001

	case 5813: // ICMPD
		return baseUtil.SRV_ICMPD
	case 143, 993: // imap4 protocol over TLS/SSL (imaps)
		return baseUtil.SRV_IMAP4

	case 102, 309: // ISO Transport Class 2 Non-Control over TCP
		return baseUtil.SRV_ISO_TSAP

	case 543: // klogin
		return baseUtil.SRV_KLOGIN
	case 544: // krcmd
		return baseUtil.SRV_KSHELL

	case 389, 636: // ldap protocol over TLS/SSL (was sldap) (ldaps)
		return baseUtil.SRV_LDAP
	case 245: // LINK
		return baseUtil.SRV_LINK

	case 513: // "remote login a la telnet; automatic authentication performed based on priviledged port numbers and distributed data bases which identify ""authentication domains"""
		return baseUtil.SRV_LOGIN

	case 1911: // Starlight Networks Multimedia Transport Protocol
		return baseUtil.SRV_MTP
	case 42: // Host Name Server
		return baseUtil.SRV_NAME

	case 138: // NETBIOS Datagram Service
		return baseUtil.SRV_NETBIOS_DGM

	case 137: // NETBIOS Name Service
		return baseUtil.SRV_NETBIOS_NS

	case 139: // NETBIOS Session Service
		return baseUtil.SRV_NETBIOS_SSN

	case 15: // Unassigned [was netstat]
		return baseUtil.SRV_NETSTAT

	case 433: // NNSP
		return baseUtil.SRV_NNSP

	case 119, 563: // nntp protocol over TLS/SSL (was snntp)
		return baseUtil.SRV_NNTP

	// TODO: service pm_dump port number
	//case: //
	//	return SRV_PM_DUMP;
	//	break;

	case 109: // Post Office Protocol Version 2
		return baseUtil.SRV_POP_2

	case 110: // Post Office Protocol Version 3
		return baseUtil.SRV_POP_3

	case 515: // spooler
		return baseUtil.SRV_PRINTER

	case 71, 72, 73, 74: // Remote Job Service (netrjs-4)
		return baseUtil.SRV_REMOTE_JOB

	case 5, 77: // any private RJE service
		return baseUtil.SRV_RJE

	case 514: // "cmd like exec
		return baseUtil.SRV_SHELL

	case 25: // Simple Mail Transfer
		return baseUtil.SRV_SMTP

	case 66, 150: // SQL-NET
		return baseUtil.SRV_SQL_NET

	case 22: // The Secure Shell (SSH) Protocol
		return baseUtil.SRV_SSH

	case 111: // SUN Remote Procedure Call
		return baseUtil.SRV_SUNRPC

	case 95: // SUPDUP
		return baseUtil.SRV_SUPDUP

	case 11: // Active Users
		return baseUtil.SRV_SYSTAT

	case 23: // Telnet
		return baseUtil.SRV_TELNET

	case 37: // Time
		return baseUtil.SRV_TIME

	case 540, 4031: // UUCP over SSL
		return baseUtil.SRV_UUCP

	case 117: // UUCP Path Service
		return baseUtil.SRV_UUCP_PATH

	case 175: // VMNET
		return baseUtil.SRV_VMNET

	case 43, 4321: // Remote Who Is (rwhois)
		return baseUtil.SRV_WHOIS
	default:
		// Private ports defined by IANA in RFC 6335 section 6:
		// Dynamic Ports, also known as the Private or Ephemeral Ports,
		// from 49152 - 65535 (never assigned)
		if fiveTuple.DstPort >= 49152 {
			return baseUtil.SRV_PRIVATE // or other?
		} else {
			return baseUtil.SRV_OTHER
		}
	}

}

func GetUDPServiceType(fiveTuple baseUtil.FiveTuple) int {

	dstPort := uint16(0)
	if fiveTuple.DstIP == config.SERVERIP {
		dstPort = fiveTuple.DstPort
	} else {
		dstPort = fiveTuple.SrcPort
	}

	switch dstPort {
	case 53: // DNS
		return baseUtil.SRV_DOMAIN_U

	case 69: // TFTP
		return baseUtil.SRV_TFTP_U

	case 123: // NTP
		return baseUtil.SRV_NTP_U

	default:
		// Defined by IANA in RFC 6335 section 6:
		// the Dynamic Ports, also known as the Private or Ephemeral Ports,
		// from 49152 - 65535 (never assigned)
		if fiveTuple.DstPort >= 49152 {
			return baseUtil.SRV_PRIVATE
		} else {
			return baseUtil.SRV_OTHER
		}
	}

}

func GetICMPServiceType(icmpType, icmpCode uint8) int {
	log.Println("ICMPType: ",icmpType,"   ICMPCode: ",icmpCode)

	switch icmpType {
	case baseUtil.ECHOREPLY:
		return baseUtil.SRV_ECR_I // Echo Reply (0)

	case baseUtil.DEST_UNREACH:
		if icmpCode == 0 { // Destination network unreachable
			return baseUtil.SRV_URP_I
		} else if icmpCode == 1 { // Destination host unreachable
			return baseUtil.SRV_URH_I
		} else {
			return baseUtil.SRV_OTH_I // Other ICMP messages;
		}

	case baseUtil.REDIRECT:
		return baseUtil.SRV_RED_I // Redirect message (5)

	case baseUtil.ECHO:
		return baseUtil.SRV_ECO_I // Echo Request (8)

	case baseUtil.TIME_EXCEEDED: // Time Exceeded (11)
		return baseUtil.SRV_TIM_I

	default:
		return baseUtil.SRV_OTH_I // Other ICMP messages;
	}
}
