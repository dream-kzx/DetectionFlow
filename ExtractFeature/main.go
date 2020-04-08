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
	device string = "\\Device\\NPF_{2CCCFA0A-FEE2-4688-BC5A-43A805A8DC67}"
	//device      string = "ens33"
	promiscuous bool = false //是否开启混杂模式
)

// func main(){
// 	i := 1
// 	fmt.Println("test debug!",i)
// }

func main() {
	featureChan := make(chan *flowFeature.FlowFeature, 5)

	go snifferAndExtract(featureChan)
	go PredictFLowInFeature(featureChan)
	startGUI()
}

func startGUI() {
	l := log.New(log.Writer(), log.Prefix(), log.Flags())
	l.Printf("Running app built at %s\n", GUI.BuiltAt)

	if err := bootstrap.Run(bootstrap.Options{
		Asset:    Asset,
		AssetDir: AssetDir,
		AstilectronOptions: astilectron.Options{
			AppName:            GUI.AppName,
			AppIconDarwinPath:  "resources/icon.icns",
			AppIconDefaultPath: "resources/icon.png",
			SingleInstance:     true,
		},
		Debug:  *GUI.Debug,
		Logger: l,
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
			GUI.W = ws[0]
			return nil
		},
		RestoreAssets: RestoreAssets,
		Windows: []*bootstrap.Window{{
			Homepage:       "index.html",
			MessageHandler: nil,
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
		l.Fatal(errors.Wrap(err, "running bootstrap failed"))
	}
}

//嗅探网络流量和特征提取
func snifferAndExtract(featureChan chan *flowFeature.FlowFeature) {
	sniffer, err := sniff.NewSniffer(featureChan)
	if err != nil {
	}

	err = sniffer.SetSnifferInterface(device, promiscuous)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("开始监听：")
	sniffer.StartSniffer()
}

func PredictFLowInFeature(featureChan chan *flowFeature.FlowFeature) {
	wf := baseUtil.MyWriteFile{}
	wf.OpenFile("feature.csv")
	write := true
	predictFlow := CallPredict.NewPredictFlow(":50051")

	attackList := []string{"normal", "DOS", "PROBE"}

	for {
		select {
		case feature := <-featureChan:
			// feature.Print()

			label := predictFlow.Predict(feature)
			if write {
				data := feature.FeatureToString()
				data += attackList[label] + ","
				data += ipToString(feature.SrcIP)
				data += strconv.Itoa(int(feature.SrcPort)) + ","
				data += ipToString(feature.DstIP)
				data += strconv.Itoa(int(feature.DstPort))
				data += "\n"
				// log.Println(data)
				wf.Write(data)
			}
			log.Println("该攻击类型为：", attackList[label])

			log.Println(feature.SrcPort, "   ", feature.SrcIP)
			log.Println(feature.DstPort, "   ", feature.DstIP)
			log.Println(feature.FeatureToString())

		}

	}
}

func ipToString(ip [4]byte) string {
	data := ""
	data += strconv.Itoa(int(ip[0])) + "."
	data += strconv.Itoa(int(ip[1])) + "."
	data += strconv.Itoa(int(ip[2])) + "."
	data += strconv.Itoa(int(ip[3])) + ","
	return data
}
