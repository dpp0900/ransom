package main

import (
	"fmt"
	"io"
	"os"
)

type Header struct {
	signiture string   //.GR4PE
	idx       []uint64 //IDXn.0xFFFFFFFFFFFF
}

type deleteddData struct {
	idx  uint64 //IDXn.0xFFFFFFFFFFFF
	data []byte //data
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

func genHeader(deleteddData deleteddData) Header {
	return Header{}
}
