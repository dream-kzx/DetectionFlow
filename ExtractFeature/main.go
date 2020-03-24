package main

import (
	"FlowDetection/CallPredict"
	"FlowDetection/baseUtil"
	"FlowDetection/flowFeature"
	"FlowDetection/sniff"
	"fmt"
	"log"
)

const (
	// device string = "\\Device\\NPF_{2CCCFA0A-FEE2-4688-BC5A-43A805A8DC67}"
	device      string = "ens33"
	promiscuous bool   = false //是否开启混杂模式
)

// func main(){
// 	i := 1
// 	fmt.Println("test debug!",i)
// }

func main() {
	featureChan := make(chan *flowFeature.FlowFeature, 5)

	sniffer, err := sniff.NewSniffer(featureChan)
	if err != nil {
		log.Fatal(err)
	}

	go PredictFLowInFeature(featureChan)

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
	write := false
	predictFlow := CallPredict.NewPredictFlow(":50051")

	attackList := []string{"normal", "DOS", "PROBE"}

	for {
		select {
		case feature := <-featureChan:
			// feature.Print()

			if write {
				wf.Write(feature.FeatureToString())
			}

			label := predictFlow.Predict(feature)
			log.Println("该攻击类型为：", attackList[label])

			log.Println(feature.SrcPort, "   ", feature.SrcIP)
			log.Println(feature.FeatureToString())

		}

	}
}
