package main

import (
	"log"
	"unsafe"

	"github.com/davecgh/go-spew/spew"
	"golang.org/x/sys/windows"

	"github.com/RSSU-Shellcode/GRT-Develop/metric"
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
	GetMetrics := GleamRT.MustFindProc("GetMetrics")

	metrics := metric.Metrics{}
	ret, _, _ := GetMetrics.Call(uintptr(unsafe.Pointer(&metrics))) // #nosec
	if ret != 0 {
		log.Fatalf("failed to call GetMetrics: 0x%X", ret)
	}
	spew.Dump(metrics)
}
