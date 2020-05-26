package baseUtil

import "time"

const (
	TcpSynTimeout     = 5 * time.Second
	TcpEstabTimeout   = 60 * time.Second
	TcpRstTimeout     = 5 * time.Second
	TcpFinTimeout     = 5 * time.Second
	TcpLastAckTimeout = 5 * time.Second
	UdpTimeout        = 10 * time.Second
	IcmpTimeout       = 10 * time.Second
)



