package main

import (
	"bytes"
	"fmt"
	"log"
	"unsafe"

	"golang.org/x/sys/windows"
)

// GleamRT is a virtual dll for get runtime methods.
var GleamRT *windows.DLL

func init() {
	var err error
	GleamRT, err = windows.LoadDLL("GleamRT.dll")
	if err != nil {
		panic("failed to load virtual runtime dll")
	}
}

func main() {
	setValue()
	getValue()
	getPointer()
}

func setValue() {
	SetValue := GleamRT.MustFindProc("IMS_SetValue")

	data := []byte{0x01, 0x02, 0x03, 0x04}

	id := uint32(0) // CommandLineA
	ret, _, _ := SetValue.Call(
		uintptr(id), uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)),
	) // #nosec
	if ret == 0 {
		log.Fatalln("failed to set value")
	}
	fmt.Println("set value:", data)
}

func getValue() {
	GetValue := GleamRT.MustFindProc("IMS_GetValue")

	id := uint32(0) // CommandLineA
	var size uint
	ret, _, _ := GetValue.Call(
		uintptr(id), 0, uintptr(unsafe.Pointer(&size)),
	) // #nosec
	if ret == 0 {
		log.Fatalln("failed to get value size")
	}

	data := make([]byte, size)
	ret, _, _ = GetValue.Call(
		uintptr(id), uintptr(unsafe.Pointer(&data[0])), 0,
	) // #nosec
	if ret == 0 {
		log.Fatalln("failed to get value")
	}

	expected := []byte{0x01, 0x02, 0x03, 0x04}
	if !bytes.Equal(expected, data) {
		log.Fatalln("get value with incorrect data")
	}

	fmt.Println("get value:", data)
}

func getPointer() {
	// GetPointer := GleamRT.MustFindProc("IMS_GetPointer")
}
