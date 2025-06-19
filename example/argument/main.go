package main

import (
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
	getValue()
	getPointer()
	erase()
	eraseAll()
}

func getValue() {
	GetValue := GleamRT.MustFindProc("AS_GetValue")

	id := uint32(2) // CommandLineA
	var size uint32
	ret, _, _ := GetValue.Call(
		uintptr(id), 0, uintptr(unsafe.Pointer(&size)),
	)
	if ret == 0 {
		log.Fatalln("invalid argument id")
	}

	value := make([]byte, size)
	ret, _, _ = GetValue.Call(
		uintptr(id), uintptr(unsafe.Pointer(&value[0])), 0,
	)
	if ret == 0 {
		log.Fatalln("invalid argument id")
	}

	fmt.Println("size:", size)
	fmt.Println("value:", string(value))
	fmt.Println("raw:", value)
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
		log.Fatalln("invalid argument id")
	}

	fmt.Println("pointer:", pointer)
	fmt.Println("size:", size)

	arg := unsafe.Slice(pointer, size)
	fmt.Println("data:", string(arg))
	fmt.Println("raw:", arg)
}

func erase() {
	Erase := GleamRT.MustFindProc("AS_Erase")

	id := uint32(1) // CommandLineA
	ret, _, _ := Erase.Call(uintptr(id))
	if ret == 0 {
		log.Fatalln("failed to erase argument")
	}
	fmt.Println("erase:", ret)

	ret, _, _ = Erase.Call(uintptr(id))
	if ret == 0 {
		log.Fatalln("failed to erase argument")
	}
}

func eraseAll() {
	EraseAll := GleamRT.MustFindProc("AS_EraseAll")

	ret, _, _ := EraseAll.Call()
	if ret == 0 {
		log.Fatalln("failed to erase all argument")
	}
	fmt.Println("erase all")
}
