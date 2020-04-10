package baseUtil

import "time"

const (
	TcpSynTimeout     = 120 * time.Second
	TcpEstabTimeout   = 5 * 24 * 3600 * time.Second
	TcpRstTimeout     = 10 * time.Second
	TcpFinTimeout     = 120 * time.Second
	TcpLastAckTimeout = 30 * time.Second
	UdpTimeout        = 180 * time.Second
	IcmpTimeout       = 30 * time.Second
)



