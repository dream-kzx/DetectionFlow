package baseUtil

const MAXSERVICENUM = 73

//Service类型
const (
	// General
	SRV_OTHER = iota
	SRV_PRIVATE

	// ICMP
	SRV_ECR_I
	SRV_URP_I
	SRV_URH_I
	SRV_RED_I
	SRV_ECO_I
	SRV_TIM_I
	SRV_OTH_I

	// UDP
	SRV_DOMAIN_U
	SRV_TFTP_U
	SRV_NTP_U

	// TCP
	SRV_IRC
	SRV_X11
	SRV_Z39_50
	SRV_AOL
	SRV_AUTH
	SRV_BGP
	SRV_COURIER
	SRV_CSNET_NS
	SRV_CTF
	SRV_DAYTIME
	SRV_DISCARD
	SRV_DOMAIN
	SRV_ECHO
	SRV_EFS
	SRV_EXEC
	SRV_FINGER
	SRV_FTP
	SRV_FTP_DATA
	SRV_GOPHER
	SRV_HARVEST
	SRV_HOSTNAMES
	SRV_HTTP
	SRV_HTTP_2784
	SRV_HTTP_443
	SRV_HTTP_8001
	SRV_ICMPD
	SRV_IMAP4
	SRV_ISO_TSAP
	SRV_KLOGIN
	SRV_KSHELL
	SRV_LDAP
	SRV_LINK
	SRV_LOGIN
	SRV_MTP
	SRV_NAME
	SRV_NETBIOS_DGM
	SRV_NETBIOS_NS
	SRV_NETBIOS_SSN
	SRV_NETSTAT
	SRV_NNSP
	SRV_NNTP
	SRV_PM_DUMP
	SRV_POP_2
	SRV_POP_3
	SRV_PRINTER
	SRV_REMOTE_JOB
	SRV_RJE
	SRV_SHELL
	SRV_SMTP
	SRV_SQL_NET
	SRV_SSH
	SRV_SUNRPC
	SRV_SUPDUP
	SRV_SYSTAT
	SRV_TELNET
	SRV_TIME
	SRV_UUCP
	SRV_UUCP_PATH
	SRV_VMNET
	SRV_WHOIS

	// This must be the last
	NUMBER_OF_SERVICES
)

//icmp类型
const (
	ECHOREPLY      = 0
	DEST_UNREACH   = 3
	SOURCE_QUENCH  = 4
	REDIRECT       = 5
	ECHO           = 8
	TIME_EXCEEDED  = 11
	PARAMETERPROB  = 12
	TIMESTAMP      = 13
	TIMESTAMPREPLY = 14
	INFO_REQUEST   = 15
	INFO_REPLY     = 16
	ADDRESS        = 17
	ADDRESSREPLY   = 18
)

const (
	INIT = iota + 1 //1 Nothing happened yet.
	SF              //2 +Normal establishment and termination. Note that this is the same
	// symbol as for state S1. You can tell the two apart because for S1 there
	// will not be any byte counts in the summary, while for SF there will be.
	//正常的建立和断开。注意,这是和状态s1相同的符号。你可以把两个分开,因为S1不会有任何字节计数,而在SF中会有

	// TCP specific
	S0 // 3+Connection attempt seen, no reply. 尝试连接，没有应答
	S1 // 4+Connection established, not terminated. 连接建立，但没有终止
	S2 //5 +Connection established and close attempt by originator seen (but no reply from responder).
	//连接建立，并看到发起者尝试关闭（但未收到响应者回复）
	S3 // 6+Connection established and close attempt by responder seen (but no reply from originator).
	//连接建立，响应者尝试关闭（但是并未收到发送者回复）
	REJ    //7 +Connection attempt rejected. 尝试连接被拒绝
	RSTOS0 // 8+Originator sent a SYN followed by a RST, we never saw a SYN-ACK from the responder.
	// 发送者发起了SYN,然后发送了RST，我们未从响应者那里看到SYN-ACK
	RSTO // 9+Connection established, originator aborted (sent a RST).
	// 连接建立，发送者终止 （发送RST）
	RSTR // 10+Established, responder aborted.
	//建立，响应者发送了RST
	SH // 11+Originator sent a SYN followed by a FIN, we never saw a SYN ACK from the responder (hence the connection was “half” open).
	//发送方发送了一个SYN,后面跟一个FIN,我们再也没有看到来自响应者的SYN ACK (因此连接只打开了一半)
	RSTRH // 12Responder sent a SYN ACK followed by a RST, we never saw a SYN from the (purported) originator.
	//响应者发送了一个SYN ACK和一个RST，我们再也没有看到，发送者发出SYN
	SHR // 13Responder sent a SYN ACK followed by a FIN, we never saw a SYN from the originator.
	// 响应者发送了一个SYN ACK, 后跟一个FIN,我们从未从发起者那里看到过SYN
	OTH // 14+No SYN seen, just midstream traffic (a “partial connection” that was not later closed).
	// 没有看到SYN， 只有中游流量（"部分连接"后来没有关闭）
	// Internal states (TCP-specific)
	ESTAB // 15 Established - ACK send by originator in S1 state; externally represented as S1
	S4    // 16 SYN ACK seen - State between INIT and (RSTRH or SHR); externally represented as OTH
	S2F   // 17 FIN send by responder in state S2 - waiting for final ACK; externally represented as S2
	S3F   // 18 FIN send by originator in state S3 - waiting for final ACK; externally represented as S3
)
