package main

import (
	"FlowDetection/GUI"
	"flag"
)

var (
	AppName string = "DetectionFlow"
	BuiltAt string
	Debug   = flag.Bool("d", true, "enables the debug mode")
	manager *GUI.Manager
	handler       *GUI.Handler
)
