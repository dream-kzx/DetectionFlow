package main

import (
	"GUI/manager"
	"GUI/parameters"
	"flag"
	"github.com/asticode/go-astikit"
	"github.com/asticode/go-astilectron"
	bootstrap "github.com/asticode/go-astilectron-bootstrap"
	"github.com/pkg/errors"
	"log"
)


func main() {
	//init manager instance
	m = manager.New(manager.GetUserHome() + "/.web").Init()
	log.Println(manager.GetUserHome())
	handler := new(Handler)
	handler.Parameters = parameters.New()
	// Init
	flag.Parse()

	l := log.New(log.Writer(), log.Prefix(), log.Flags())
	l.Printf("Running app built at %s\n", BuiltAt)

	if err := bootstrap.Run(bootstrap.Options{
		Asset:    Asset,
		AssetDir: AssetDir,
		AstilectronOptions: astilectron.Options{
			AppName:            AppName,
			AppIconDarwinPath:  "resources/icon.icns",
			AppIconDefaultPath: "resources/icon.png",
			SingleInstance:     true,
		},
		Debug:  *debug,
		Logger: l,
		RestoreAssets: RestoreAssets,
		OnWait: func(_ *astilectron.Astilectron, ws []*astilectron.Window, _ *astilectron.Menu, _ *astilectron.Tray, _ *astilectron.Menu) error {
			m.Window = ws[0]
			return nil
		},
		MenuOptions: []*astilectron.MenuItemOptions{{
			Label: astikit.StrPtr("File"),
			SubMenu: []*astilectron.MenuItemOptions{
				//{
				//	Label: astikit.StrPtr("About"),
				//	OnClick: func(e astilectron.Event) (deleteListener bool) {
				//		//if err := bootstrap.SendMessage(w, "NewGroup", htmlAbout, func(m *bootstrap.MessageIn) {
				//		//	// Unmarshal payload
				//		//	var s string
				//		//	if err := json.Unmarshal(m.Payload, &s); err != nil {
				//		//		astilog.Error(errors.Wrap(err, "unmarshaling payload failed"))
				//		//		return
				//		//	}
				//		//	astilog.Infof("About modal has been displayed and payload is %s!", s)
				//		//}); err != nil {
				//		//	astilog.Error(errors.Wrap(err, "sending about event failed"))
				//		//}
				//		return
				//	},
				//},
				//{
				//	Label: astikit.StrPtr("New"),
				//	OnClick: func(e astilectron.Event) (deleteListener bool) {
				//		//if err := bootstrap.SendMessage(w, "NewGroup", htmlAbout, func(m *bootstrap.MessageIn) {
				//		//	// Unmarshal payload
				//		//	var s string
				//		//	if err := json.Unmarshal(m.Payload, &s); err != nil {
				//		//		astilog.Error(errors.Wrap(err, "unmarshaling payload failed"))
				//		//		return
				//		//	}
				//		//	astilog.Infof("About modal has been displayed and payload is %s!", s)
				//		//}); err != nil {
				//		//	astilog.Error(errors.Wrap(err, "sending about event failed"))
				//		//}
				//		return
				//	},
				//},
				{Role: astilectron.MenuItemRoleReload},
				{Role: astilectron.MenuItemRoleToggleFullScreen},
				{Role: astilectron.MenuItemRoleClose},
			},
		}},
		Windows: []*bootstrap.Window{{
			Homepage:       "index.html",
			MessageHandler: handler.handleMessages,
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

func handleMessages(w *astilectron.Window,
	messageIn bootstrap.MessageIn) (payload interface{}, err error) {

	return
}
