package config

import (
	"encoding/json"
	"io/ioutil"
	"strconv"
	"strings"
	"log"
)


var (
	SERVERIP = [4]byte{192, 168, 234, 128}
	// SERVERIP = [4]byte{192, 168, 0, 103}
	DEBUG    = false

	ServerRootPasswd = "kzx123**"
)

func init(){

	jsonParse := NewJsonStruct()
	v := ServerConfig{}

	jsonParse.Load("config/config.json",&v)

	ip := strings.Split(v.ServerIp, ".")

	var serverIp [4]byte
	i := 0
	for _, v := range ip {
		if i >=4{
			break
		}

		k, err := strconv.Atoi(v)
		if err!=nil{
			break
		}
		serverIp[i] = byte(k)
		i++
	}

	copy(SERVERIP[:], serverIp[:])
	log.Println(SERVERIP)
}


type ServerConfig struct {
	ServerIp string
}

type JsonStruct struct {

}

func NewJsonStruct () *JsonStruct{
	return &JsonStruct{}
}

func (js *JsonStruct) Load(fileName string, v interface{}){
	data, err := ioutil.ReadFile(fileName)
	if err!=nil{
		return
	}

	err = json.Unmarshal(data,v)
	if err!=nil{
		return
	}
}

