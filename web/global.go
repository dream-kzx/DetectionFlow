package main

import (
	"GUI/manager"
	"flag"
	"github.com/asticode/go-astilectron"
)

var (
	AppName string = "DetectionFlow"
	BuiltAt string
	debug   = flag.Bool("d", true, "enables the debug mode")
	w       *astilectron.Window
	m       *manager.Manager
	h       *Handler
)