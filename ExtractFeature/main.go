package main

import (
	"FlowDetection/CallPredict"
	"FlowDetection/GUI"
	"FlowDetection/baseUtil"
	"FlowDetection/flowFeature"
	"FlowDetection/sniff"
	"fmt"
	"github.com/asticode/go-astikit"
	"github.com/asticode/go-astilectron"
	bootstrap "github.com/asticode/go-astilectron-bootstrap"
	"github.com/pkg/errors"
	"log"
	"strconv"
)

const (
	promiscuous bool = false //是否开启混杂模式
)


func main() {
	//解析命令行参数
	parseParameters()

	if queryNetworkCard {
		PrintNetworkCard()
		return
	}

	//黑名单到sniffer捕获ip的操作信道
	BlackToSnifferChan = make(chan *GUI.OperateSniffer)

	//特征结构-->预测的chan
	featureToPredictChan := make(chan *flowFeature.FlowFeature, 5)

	manager = GUI.NewManager()
	handler = GUI.NewHandler(manager, BlackToSnifferChan, &AutoFilter)

	//启动预测模块
	go PredictFLowInFeature(featureToPredictChan)

	if GUIStart {
		resultToGUIChan = make(chan *GUI.FlowResult, 10)
		go snifferAndExtract(featureToPredictChan)

		startGUI()
	} else {
		snifferAndExtract(featureToPredictChan)
	}
}

//以GUI界面运行
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
		Debug:  Debug,
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

//启动嗅探网卡和提取特征
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
	} else if *pcapFileName != "" {
		err = sniffer.SetSnifferSource(*pcapFileName, 0, promiscuous)
		if err != nil {
			log.Fatal(err)
		}
	}

	fmt.Println("开始监听：")

	sniffer.StartSniffer(BlackToSnifferChan, &WritePcap)
}

//打印网卡的信息
func PrintNetworkCard() {
	sniffer, err := sniff.NewSniffer(nil)
	if err != nil {
		log.Fatal(err)
	}
	sniffer.PrintDevices()
}

//预测流量类型
func PredictFLowInFeature(featureChan chan *flowFeature.FlowFeature) {

	//写feature.csv文件
	if WriteCsv {
		wf = baseUtil.MyWriteFile{}
		wf.OpenFile("feature.csv")
	}

	predictFlow := CallPredict.NewPredictFlow(":50051")

	attackList := []string{"normal", "attack"}

	for {
		select {
		case feature := <-featureChan:
			//grpc调用机器学习算法，预测流量类型
			label := predictFlow.Predict(feature)

			if WriteCsv {
				data := baseUtil.IpToString(feature.SrcIP) + ","
				data += strconv.Itoa(int(feature.SrcPort)) + ","
				data += baseUtil.IpToString(feature.DstIP) + ","
				data += strconv.Itoa(int(feature.DstPort))+","
				data += feature.FeatureToString()
				data += attackList[label]
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

			if GUIStart {
				resultToGUIChan <- flowResult
			} else {
				manager.AddFlow(flowResult)
			}

		}

	}
}
