package main

import (
	"fmt"
	"log"
	"time"

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
	var (
		Kick   = GleamRT.MustFindProc("WD_Kick")
		Enable = GleamRT.MustFindProc("WD_Enable")
	)
	ret, _, _ := Enable.Call()
	if ret != 0 {
		log.Printf("[warning] failed to enable watchdog: 0x%X\n", ret)
		return
	}

	go func() {
		for {
			fmt.Println("application is healthy")

			fmt.Println("kick watchdog")
			ret, _, _ = Kick.Call()
			if ret != 0 {
				log.Fatalf("failed to kick watchdog: 0x%X\n", ret)
			}
			time.Sleep(time.Second)
		}
	}()

	time.Sleep(3 * time.Second)
}
