package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

var (
	modKernel32 = windows.NewLazyDLL("kernel32.dll")

	procSleep = modKernel32.NewProc("Sleep")
)

func main() {
	data := strings.Repeat("secret", 1)

	for i := 0; i < 3; i++ {
		sleep(time.Second)
		fmt.Println("sleep complete")
	}

	fmt.Println(data)
}

func sleep(d time.Duration) {
	ret, _, _ := procSleep.Call(uintptr(d.Milliseconds()))
	if ret != 0 {
		log.Fatalf("sleep returned errno: 0x%X\n", ret)
	}
}
