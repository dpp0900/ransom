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
	if e != nil {
		panic(e)
	}
}
func readByte(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	fileSize := fileInfo.Size()
	fileBytes := make([]byte, fileSize)
	bytesRead := 0
	for bytesRead < int(fileSize) {
		n, err := file.Read(fileBytes[bytesRead:])
		if err != nil && err != io.EOF {
			return nil, err
		}
		if n == 0 {
			break
		}
		bytesRead += n
	}
	return fileBytes, nil
}
func tt() {
	// 입력 파일 이름과 출력 파일 이름을 지정합니다.
	inputFileName := "1080p가세혁-해킹시연동영상공모전.mp4"
	outputFileName := "output.txt"

	// 입력 파일 열기
	inputFile, err := os.Open(inputFileName)
	if err != nil {
		fmt.Println("파일 열기 실패:", err)
		return
	}
	defer inputFile.Close()

	// 출력 파일 생성
	outputFile, err := os.Create(outputFileName)
	if err != nil {
		fmt.Println("파일 생성 실패:", err)
		return
	}
	defer outputFile.Close()

	// 입력 파일에서 앞 8192 바이트를 읽고 버립니다.
	_, err = io.CopyN(io.Discard, inputFile, 8192)
	if err != nil && err != io.EOF {
		fmt.Println("파일 처리 실패:", err)
		return
	}

	// 나머지 내용을 출력 파일로 복사합니다.
	_, err = io.Copy(outputFile, inputFile)
	if err != nil {
		fmt.Println("파일 복사 실패:", err)
		return
	}

	fmt.Println("파일 처리 완료")
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
	buf, err := readByte(inputFileName)
	check(err)
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
}
