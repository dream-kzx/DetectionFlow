package main

import (
	"FlowDetection/GUI"
	"FlowDetection/baseUtil"
	"flag"
	"log"
	"runtime"
)

var (
	AppName string = "DetectionFlow"
	BuiltAt string
	manager *GUI.Manager
	handler *GUI.Handler
)

var (
	BlackToSnifferChan chan *GUI.OperateSniffer
	resultToGUIChan    chan *GUI.FlowResult
	logOut             *log.Logger

	Debug            bool
	queryNetworkCard bool    //查询网卡信息
	device           *string //网卡名称
	pcapFileName     *string //pacp文件名
	GUIStart         bool    //使用GUI
	AutoFilter       bool    //自动过滤
	WritePcap        bool    //写pacp，feature文件
	WriteCsv         bool

	wf baseUtil.MyWriteFile
)

func parseParameters() {

	flag.BoolVar(&queryNetworkCard, "i", false, "查询本机网卡的信息")

	device = flag.String("device", "", "要嗅探的网卡名称")
	pcapFileName = flag.String("pcapFileName", "", "要解析的文件路径名称")

	flag.BoolVar(&AutoFilter, "auto", false, "是否在异常连接数达到阈值时，自动加入IP黑名单")
	flag.BoolVar(&GUIStart, "gui", false, "是否启动GUI界面")
	flag.BoolVar(&WritePcap, "wp", false, "是否允许缓存pcap文件")
	flag.BoolVar(&WriteCsv, "wc", false, "是否允许缓存feature文件")
	flag.BoolVar(&Debug, "d", false, "开启Debug模块")

	flag.Parse()

	log.Println(AutoFilter)
	if *device == "" && *pcapFileName == "" {
		osStr := runtime.GOOS
		if osStr == "linux" || osStr == "unix" {
			*device = "ens33"
		} else if osStr == "windows" {
			*device = "\\Device\\NPF_{2CCCFA0A-FEE2-4688-BC5A-43A805A8DC67}"
		}
	}

}
