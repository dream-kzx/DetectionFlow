package main

import (
	"FlowDetection/CallPredict"
	"FlowDetection/baseUtil"
	"FlowDetection/flowFeature"
	"FlowDetection/sniff"
	"fmt"
	"log"
	"strconv"
)

const (
	device string = "\\Device\\NPF_{2CCCFA0A-FEE2-4688-BC5A-43A805A8DC67}"
	// device      string = "ens33"
	promiscuous bool = true //是否开启混杂模式
)

func main() {

	featureChan := make(chan *flowFeature.FlowFeature, 5)

	go snifferAndExtract(featureChan)

	go PredictFLowInFeature(featureChan)
}

func snifferAndExtract(featureChan chan *flowFeature.FlowFeature) {
	sniffer, err := sniff.NewSniffer(featureChan)
	if err != nil {
		log.Fatal(err)
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
