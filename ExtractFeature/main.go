package main

import (
	"FlowDetection/CallPredict"
	"FlowDetection/GUI"
	"FlowDetection/baseUtil"
	"FlowDetection/flowFeature"
	"FlowDetection/sniff"
	"flag"
	"fmt"
	"github.com/asticode/go-astikit"
	"github.com/asticode/go-astilectron"
	bootstrap "github.com/asticode/go-astilectron-bootstrap"
	"github.com/pkg/errors"
	"log"
	"runtime"
	"strconv"
)

const (
	promiscuous bool = false //是否开启混杂模式
)

var (
	BlackToSnifferChan chan *GUI.OperateSniffer
	resultToGUIChan    chan *GUI.FlowResult
	logOut             *log.Logger

	queryNetworkCard bool //查询网卡信息
	device       *string //网卡名称
	pcapFileName *string //pacp文件名
	GUIStart     *bool   //使用GUI
	AutoFilter   *bool   //自动过滤
	WriteFile    *bool   //写pacp，feature文件

	wf baseUtil.MyWriteFile
)


func parseParameters() {
	flag.BoolVar(&queryNetworkCard,"i",false,"查询本机网卡的信息")

	device = flag.String("device", "", "要嗅探的网卡名称")
	pcapFileName = flag.String("pcapFileName", "", "要解析的文件路径名称")

	flag.BoolVar(AutoFilter,"auto",true,"是否在异常连接数达到阈值时，自动加IP假如黑名单")
	flag.BoolVar(GUIStart,"gui",false,"是否启动GUI界面")
	flag.BoolVar(WriteFile,"wf",false,"是否允许保存pcap，feature文件")


	flag.Parse()

	if *device == "" && *pcapFileName == ""{
		osStr := runtime.GOOS
		if osStr == "linux" || osStr == "unix" {
			*device = "ens33"
		} else if osStr == "windows" {
			*device = "\\Device\\NPF_{2CCCFA0A-FEE2-4688-BC5A-43A805A8DC67}"
		}
	}

}

func main() {
	//解析命令行参数
	parseParameters()

	if queryNetworkCard {
		PrintNetworkCard()
	}

	//黑名单到sniffer捕获ip的操作信道
	BlackToSnifferChan = make(chan *GUI.OperateSniffer)

	//特征结构-->预测的chan
	featureToPredictChan := make(chan *flowFeature.FlowFeature, 5)

	manager = GUI.NewManager()
	handler = GUI.NewHandler(manager, BlackToSnifferChan, AutoFilter)

	//启动预测模块
	go PredictFLowInFeature(featureToPredictChan)

	if *GUIStart {
		resultToGUIChan = make(chan *GUI.FlowResult, 10)
		go snifferAndExtract(featureToPredictChan)

		startGUI()
	} else {
		snifferAndExtract(featureToPredictChan)
	}
}

func startGUI() {
	logOut = log.New(log.Writer(), log.Prefix(), log.Flags())
	logOut.Printf("Running app built at %s\n", BuiltAt)

	if err := bootstrap.Run(bootstrap.Options{
		Asset:    Asset,
		AssetDir: AssetDir,
		AstilectronOptions: astilectron.Options{
			AppName:            AppName,
			AppIconDarwinPath:  "resources/icon.icns",
			AppIconDefaultPath: "resources/icon.png",
			SingleInstance:     true,
			ElectronSwitches:   []string{"--no-sandbox"},
		},
		Debug:  *Debug,
		Logger: logOut,
		MenuOptions: []*astilectron.MenuItemOptions{{
			Label: astikit.StrPtr("File"),
			SubMenu: []*astilectron.MenuItemOptions{
				{Role: astilectron.MenuItemRoleReload},
				{Role: astilectron.MenuItemRoleToggleFullScreen},
				{Role: astilectron.MenuItemRoleToggleDevTools},
			},
		}},
		OnWait: func(_ *astilectron.Astilectron, ws []*astilectron.Window,
			_ *astilectron.Menu, _ *astilectron.Tray, _ *astilectron.Menu) error {
			manager.W = ws[0]
			go func() {
				for flowResult := range resultToGUIChan {
					manager.AddFlow(flowResult)
					manager.SendHostMessage(flowResult.SrcIP)
				}

			}()
			return nil
		},
		RestoreAssets: RestoreAssets,
		Windows: []*bootstrap.Window{{
			Homepage:       "index.html",
			MessageHandler: handler.HandleMessages,
			Options: &astilectron.WindowOptions{
				BackgroundColor: astikit.StrPtr("#2d3e50"),
				Center:          astikit.BoolPtr(true),
				Height:          astikit.IntPtr(650),
				Width:           astikit.IntPtr(950),
				MinHeight:       astikit.IntPtr(650),
				MinWidth:        astikit.IntPtr(950),
			},
		}},
	}); err != nil {
		logOut.Fatal(errors.Wrap(err, "running bootstrap failed"))
	}
}

func snifferAndExtract(featureChan chan *flowFeature.FlowFeature) {
	sniffer, err := sniff.NewSniffer(featureChan)
	if err != nil {
		log.Fatal(err)
	}

	if *device != "" {
		err = sniffer.SetSnifferSource(*device, 1, promiscuous)
		if err != nil {
			log.Fatal(err)
		}
	}else if *pcapFileName !=""{
		err = sniffer.SetSnifferSource(*pcapFileName, 0, promiscuous)
		if err != nil {
			log.Fatal(err)
		}
	}


	fmt.Println("开始监听：")

	sniffer.StartSniffer(BlackToSnifferChan, WriteFile)
}

func PrintNetworkCard(){
	sniffer, err := sniff.NewSniffer(nil)
	if err != nil {
		log.Fatal(err)
	}
	sniffer.PrintDevices()
}

func PredictFLowInFeature(featureChan chan *flowFeature.FlowFeature) {

	//写feature.csv文件
	if *WriteFile {
		wf = baseUtil.MyWriteFile{}
		wf.OpenFile("feature.csv")
	}

	predictFlow := CallPredict.NewPredictFlow(":50051")

	attackList := []string{"normal", "DOS", "PROBE"}

	for {
		select {
		case feature := <-featureChan:
			//grpc调用机器学习算法，预测流量类型
			label := predictFlow.Predict(feature)

			if *WriteFile {
				data := feature.FeatureToString()
				data += attackList[label] + ","
				data += baseUtil.IpToString(feature.SrcIP) + ","
				data += strconv.Itoa(int(feature.SrcPort)) + ","
				data += baseUtil.IpToString(feature.DstIP) + ","
				data += strconv.Itoa(int(feature.DstPort))
				data += "\n"
				// log.Println(data)
				wf.Write(data)
			}

			log.Println("该攻击类型为：", attackList[label])

			log.Println(feature.SrcPort, "   ", feature.SrcIP)
			log.Println(feature.DstPort, "   ", feature.DstIP)
			log.Println(feature.FeatureToString())

			//
			flowResult := new(GUI.FlowResult)
			flowResult.SrcIP = baseUtil.IpToString(feature.SrcIP)
			flowResult.SrcPort = strconv.Itoa(int(feature.SrcPort))
			flowResult.AttackType = attackList[label]

			if *GUIStart {
				resultToGUIChan <- flowResult
			} else {
				manager.AddFlow(flowResult)
			}

		}

	}
}
