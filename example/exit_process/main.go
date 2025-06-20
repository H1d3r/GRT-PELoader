package main

import (
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
	exitProcess(1)
}

func exitProcess(code int) {
	ExitProcess := GleamRT.MustFindProc("ExitProcess")

	_, _, _ = ExitProcess.Call(uintptr(code))
}
