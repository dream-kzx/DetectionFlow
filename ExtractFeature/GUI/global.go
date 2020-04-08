package GUI

import (
	"flag"
	"github.com/asticode/go-astilectron"
	_ "github.com/asticode/go-astilectron"
)

var (
	AppName string = "DetectionFlow"
	BuiltAt string
	Debug   = flag.Bool("d", true, "enables the debug mode")
	W  *astilectron.Window
	m       *manager.Manager
	h       *Handler
)