package GUI

import (
	"encoding/json"
	"github.com/asticode/go-astilectron"
	bootstrap "github.com/asticode/go-astilectron-bootstrap"
	"reflect"
)

type Handler struct {
	Parameter *Parameters
	blackList map[string]interface{}
	manager   *Manager
}

func NewHandler(manager *Manager) *Handler {
	handle := new(Handler)
	handle.manager = manager
	handle.Parameter = NewParameters()
	handle.blackList = make(map[string]interface{})
	return handle
}

type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Payload interface{} `json:"payload"`
}

func (h *Handler) toFirstCharUpper(str string) string {
	r := []rune(str)
	if r[0] >= 97 && r[0] <= 122 {
		r[0] -= 32
	}
	return string(r)
}

func (h *Handler) HandleMessages(_ *astilectron.Window,
	messageIn bootstrap.MessageIn) (payload interface{}, handleErr error) {

	var data map[string]interface{}
	data = make(map[string]interface{})
	if err := json.Unmarshal(messageIn.Payload, &data); err != nil {
		payload = nil
		return
	}

	h.Parameter.Form(data)
	reflectVal := reflect.ValueOf(h)
	method := reflectVal.MethodByName(
		h.toFirstCharUpper(messageIn.Name) + "Handler")

	if method.IsValid() {
		retVal := method.Call(nil)
		return retVal[0].Interface().(Response), nil
	}
	return Response{Code: 0, Message: "Not Found"}, nil
}
