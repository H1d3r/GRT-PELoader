package main

import (
	"fmt"
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
	getValue()
	getPointer()
}

func getValue() {
	GetValue := GleamRT.MustFindProc("AS_GetValue")

	id := uint32(2) // CommandLineA
	value := make([]byte, 4096)
	var size uint32
	ret, _, _ := GetValue.Call(
		uintptr(id), uintptr(unsafe.Pointer(&value[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret == 0 {
		fmt.Println("invalid argument id")
		return
	}

	fmt.Println("size:", size)
	fmt.Println("value:", string(value[:size]))
	fmt.Println("raw:", value[:size])
}

func getPointer() {
	GetPointer := GleamRT.MustFindProc("AS_GetPointer")

	id := uint32(2) // CommandLineA
	var (
		pointer *byte
		size    uint32
	)
	ret, _, _ := GetPointer.Call(
		uintptr(id), uintptr(unsafe.Pointer(&pointer)),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret == 0 {
		fmt.Println("invalid argument id")
		return
	}

	fmt.Println("pointer:", pointer)
	fmt.Println("size:", size)

	arg := unsafe.Slice(pointer, size)
	fmt.Println("data:", string(arg))
	fmt.Println("raw:", arg)
}
