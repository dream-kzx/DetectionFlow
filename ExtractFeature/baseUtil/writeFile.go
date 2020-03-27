package baseUtil

import (
	"io"
	"os"
)

func (w *MyWriteFile) check(e error) {
	if e != nil {
		panic(e)
	}
}

func CheckFileIsExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}

	return exist
}

type MyWriteFile struct {
	f *os.File
}

func (w *MyWriteFile) OpenFile(filename string) {
	var err error

	if CheckFileIsExist(filename) {
		_ = os.Remove(filename)

		// w.f, err = os.OpenFile(filename, os.O_APPEND, 0777)
	}
	w.f, err = os.Create(filename)
	data := "protocol_type,service,flag,src_bytes,same_srv_rate,dst_host_srv_count,dst_host_same_srv_rate," +
		"dst_host_diff_srv_rate,dst_host_srv_serror_rate,label,srcIP,srcPort,dstIP,dstPort\n"
	// data := "duration,protocol_type,service,flag,src_bytes,dst_bytes,land," +
	// 	"wrong_fragment,urgent,hot,num_failed_logins,logged_in,num_compromised,root_shell,su_attempted," +
	// 	"num_root,num_file_creations,num_shells,num_access_files,num_outbound_cmds,is_hot_login,is_guest_login," +
	// 	"count,srv_count,serror_rate,srv_serror_rate,rerror_rate,srv_rerror_rate,same_srv_rate,diff_srv_rate," +
	// 	"srv_diff_host_rate,dst_host_count,dst_host_srv_count,dst_host_same_srv_rate,dst_host_diff_srv_rate," +
	// 	"dst_host_same_src_port_rate,dst_host_srv_diff_host_rate,dst_host_serror_rate,dst_host_srv_serror_rate," +
	// 	"dst_host_rerror_rate,dst_host_srv_rerror_rate,label\n"

	w.Write(data)

	w.check(err)
	return
}

func (w *MyWriteFile) Write(data string) {
	_, err := io.WriteString(w.f, data)
	w.check(err)
}