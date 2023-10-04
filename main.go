package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

type Header struct {
	signiture []byte //.GR4PE
	idx       []byte //IDXn.0xFFFFFFFFFFFF
}

type deletedData struct {
	idx  uint64 //IDXn.0xFFFFFFFFFFFF
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
	for i := int64(0); i < offset/4096; i++ {
		buf := make([]byte, 4096)
		readNwriteBuf(wfile, rfile, buf)
	}
	buf := make([]byte, offset%4096)
	readNwriteBuf(wfile, rfile, buf)
	_, err = rfile.Seek(length, 1)
	check(err)
	buf = make([]byte, 4096-(offset%4096)-length)
	readNwriteBuf(wfile, rfile, buf)
	for i := int64(0); i < (fileInfo.Size()-(offset+length))/4096; i++ {
		buf := make([]byte, 4096)
		readNwriteBuf(wfile, rfile, buf)
	}
	buf = make([]byte, (fileInfo.Size()-(offset+length))%4096)
	readNwriteBuf(wfile, rfile, buf)
	return string(ret), nil
}

func genHeader(deletedData []deletedData) []byte {
	var idx []byte
	var cnt int
	for _, v := range deletedData {
		idx = append(idx, []byte(
			"IDX"+strconv.Itoa(cnt)+string(
				[]byte(".0x"+
					strings.Repeat("0", (12-len(strconv.FormatUint(v.idx, 16))))+
					strconv.FormatUint(v.idx, 16))))...,
		)
		cnt++
	}
	return append([]byte(".GR4PE"), idx...)
}

func main() {
	inputFileName := "tmpfile/in/test"
	buf, err := removeByte(inputFileName, 40, 10)
	check(err)
	fmt.Println(buf)
	/*
		fmt.Print(genHeader([]deletedData{
			{
				idx:  0x000000000100,
				data: buf,
			},
			{
				idx:  0x000000000001,
				data: []byte("test2"),
			},
			{
				idx:  0x000000000002,
				data: []byte("test3"),
			},
		}))
	*/
}
