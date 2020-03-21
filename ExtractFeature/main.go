package main

import (
	"FlowDetection/sniff"
	"log"
)

const (
	device      string = "\\Device\\NPF_{2CCCFA0A-FEE2-4688-BC5A-43A805A8DC67}"
	promiscuous bool   = false //是否开启混杂模式
)

func main() {

	sniffer, err := sniff.NewSniffer()
	if err != nil {
		log.Fatal(err)
	}

	err = sniffer.SetSnifferInterface(device, promiscuous)
	if err != nil {
		log.Fatal(err)
	}

	sniffer.StartSniffer()

}
