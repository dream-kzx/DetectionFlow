package GUI

import (
	"encoding/json"
	"github.com/asticode/go-astilectron"
	bootstrap "github.com/asticode/go-astilectron-bootstrap"
)

type Handler struct {
}

func (h *Handler) toFirstCharUpper(str string) string {
	r := []rune(str)
	if r[0] >= 97 && r[0] <= 122 {
		r[0] -= 32
	}
	return string(r)
}

func (h *Handler) handleMessages(w *astilectron.Window,
	messageIn bootstrap.MessageIn)(payload interface{}, handleErr error){

	var data map[string]interface{}
	data = make(map[string]interface{})
	if err := json.Unmarshal(messageIn.Payload,&data);err!=nil{
		payload = nil
		return
	}


}
