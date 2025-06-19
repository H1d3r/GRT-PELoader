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
	deleteVal()
	deleteAll()
}

func setValue() {
	SetValue := GleamRT.MustFindProc("IMS_SetValue")

	data := []byte{0x01, 0x02, 0x03, 0x04}

	id := int32(0)
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

	id := int32(0)
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
	GetPointer := GleamRT.MustFindProc("IMS_GetPointer")

	id := int32(0)
	var (
		pointer *byte
		size    uint32
	)
	ret, _, _ := GetPointer.Call(
		uintptr(id), uintptr(unsafe.Pointer(&pointer)),
		uintptr(unsafe.Pointer(&size)),
	) // #nosec
	if ret == 0 {
		log.Fatalln("invalid value id")
	}
	fmt.Println("pointer:", pointer)
	fmt.Println("size:", size)

	data := unsafe.Slice(pointer, size) // #nosec
	expected := []byte{0x01, 0x02, 0x03, 0x04}
	if !bytes.Equal(expected, data) {
		log.Fatalln("get value with incorrect data")
	}
	fmt.Println("get value:", data)
}

func deleteVal() {
	Delete := GleamRT.MustFindProc("IMS_Delete")

	id := int32(0)
	ret, _, _ := Delete.Call(uintptr(id))
	if ret == 0 {
		log.Fatalln("invalid value id")
	}

	ret, _, _ = Delete.Call(uintptr(id))
	if ret == 1 {
		log.Fatalln("invalid value id")
	}
	fmt.Println("delete value:", id)
}

func deleteAll() {
	DeleteAll := GleamRT.MustFindProc("IMS_DeleteAll")

	ret, _, _ := DeleteAll.Call()
	if ret == 0 {
		log.Fatalln("failed to delete all data")
	}
	fmt.Println("delete all data")
}
