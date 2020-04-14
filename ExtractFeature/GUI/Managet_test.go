package GUI

import (
	"log"
	"testing"
)

func TestHandler_AddBlackListHandler(t *testing.T) {
	manager := NewManager()
	handle := NewHandler(manager)

	for i:=0;i<3;i++{
		manager.AddFlow(&flowResults[i])
	}

	handle.manager.hostList["123.123.123.123"].Enabled=true

	for i:=3;i<len(flowResults);i++{
		manager.AddFlow(&flowResults[i])
	}

	for n := range handle.manager.hostList{
		log.Println(n)
	}
}



var(
	flowResults = []FlowResult{
		{
			SrcIP:      "123.123.123.123",
			SrcPort:    "80",
			AttackType: "normal",
		},
		{
			SrcIP:      "123.123.123.123",
			SrcPort:    "81",
			AttackType: "normal",
		},
		{
			SrcIP:      "123.123.123.123",
			SrcPort:    "82",
			AttackType: "normal",
		},
		{
			SrcIP:      "123.123.123.123",
			SrcPort:    "83",
			AttackType: "normal",
		},
		{
			SrcIP:      "123.123.123.123",
			SrcPort:    "84",
			AttackType: "normal",
		},
		{
			SrcIP:      "123.123.123.123",
			SrcPort:    "85",
			AttackType: "normal",
		},

	}
)