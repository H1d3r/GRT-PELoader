//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"reflect"
	"syscall"
	"time"
	"unsafe"

	"github.com/RSSU-Shellcode/Gleam-RT/runtime"
	"github.com/davecgh/go-spew/spew"

	"golang.org/x/sys/windows"
)

const (
	null    = 0
	noError = 0
)

var (
	modKernel32            = windows.NewLazyDLL("kernel32.dll")
	procGetCurrentThreadID = modKernel32.NewProc("GetCurrentThreadId")
	procSleep              = modKernel32.NewProc("Sleep")
)

var GleamRT *windows.DLL

func init() {
	var err error
	GleamRT, err = windows.LoadDLL("GleamRT.dll")
	if err != nil {
		fmt.Println("[warning] failed to load virtual runtime dll")
		return
	}
	fmt.Println("[info] virtual runtime dll loaded")
}

func main() {
	testRuntimeAPI()
	testMemoryData()
	testGoRoutine()
	testLargeBuffer()
	testHTTPServer()
	testHTTPClient()
	testWatchdog()
	testGetMetric()
	kernel32Sleep()

	for {
		fmt.Println("keep alive")
		time.Sleep(250 * time.Millisecond)
	}
}

func testRuntimeAPI() {
	hGleamRT := GleamRT.Handle
	hKernel32 := modKernel32.Handle()

	// find runtime methods
	for _, proc := range []string{
		"GetProcAddressByName",
		"GetProcAddressByHash",
		"GetProcAddressOriginal",
		"GetMetrics",
		"ExitProcess",

		"AS_GetValue",
		"AS_GetPointer",
		"AS_Erase",
		"AS_EraseAll",

		"IMS_SetValue",
		"IMS_GetValue",
		"IMS_GetPointer",
		"IMS_Delete",
		"IMS_DeleteAll",

		"SM_Pause",
		"SM_Continue",

		"WD_Kick",
		"WD_Enable",
		"WD_Disable",
		"WD_IsEnabled",
		"WD_SetHandler",
		"WD_Pause",
		"WD_Continue",
	} {
		dllProcAddr := GleamRT.MustFindProc(proc).Addr()
		getProcAddr, err := windows.GetProcAddress(hGleamRT, proc)
		checkError(err)
		if dllProcAddr != getProcAddr {
			log.Fatalln("unexpected proc address")
		}
		fmt.Printf("%s: 0x%X\n", proc, dllProcAddr)
	}
	fmt.Println()

	// get original GetProcAddress
	GetProcAddressOriginal, err := windows.GetProcAddress(hGleamRT, "GetProcAddressOriginal")
	checkError(err)
	procName, err := syscall.BytePtrFromString("GetProcAddress")
	checkError(err)
	ret, _, _ := syscall.SyscallN(
		GetProcAddressOriginal,
		hKernel32, (uintptr)(unsafe.Pointer(procName)), // #nosec
	)
	if ret == null {
		log.Fatalln("failed to get GetProcAddress address")
	}
	// get hooked GetProcAddress
	GetProcAddress := modKernel32.NewProc("GetProcAddress").Addr()
	fmt.Printf("Original GetProcAddress: 0x%X\n", ret)
	fmt.Printf("Hooked   GetProcAddress: 0x%X\n", GetProcAddress)

	// get original VirtualAlloc
	procName, err = syscall.BytePtrFromString("VirtualAlloc")
	checkError(err)
	ret, _, _ = syscall.SyscallN(
		GetProcAddressOriginal,
		hKernel32, (uintptr)(unsafe.Pointer(procName)), // #nosec
	)
	if ret == null {
		log.Fatalln("failed to get VirtualAlloc address")
	}
	// get hooked VirtualAlloc
	VirtualAlloc, err := syscall.GetProcAddress(syscall.Handle(hKernel32), "VirtualAlloc")
	checkError(err)
	fmt.Printf("Original VirtualAlloc: 0x%X\n", ret)
	fmt.Printf("Hooked   VirtualAlloc: 0x%X\n", VirtualAlloc)

	err = GleamRT.Release()
	checkError(err)

	// check msvcrt.dll
	dll := syscall.NewLazyDLL("msvcrt.dll")
	proc := dll.NewProc("malloc")
	fmt.Printf("msvcrt.malloc: 0x%X\n", proc.Addr())
	proc = dll.NewProc("free")
	fmt.Printf("msvcrt.free:   0x%X\n", proc.Addr())
	fmt.Println()
}

var globalVar = 12345678

func testMemoryData() {
	go func() {
		localVar := 12121212
		localStr := "hello GleamRT"

		for {
			tid, _, _ := procGetCurrentThreadID.Call()
			fmt.Println("Thread ID:", tid)

			fmt.Printf("global variable pointer: 0x%X\n", &globalVar)
			fmt.Println("global variable value:  ", globalVar)

			fmt.Printf("local variable pointer:  0x%X\n", &localVar)
			fmt.Println("local variable value:   ", localVar)

			funcAddr := reflect.ValueOf(testRuntimeAPI).Pointer()
			fmt.Printf("instruction:             0x%X\n", funcAddr)

			inst := unsafe.Slice((*byte)(unsafe.Pointer(funcAddr)), 8) // #nosec
			fmt.Printf("instruction data:        %v\n", inst)

			time.Sleep(time.Second)
			fmt.Println(localStr, "finish!")
			fmt.Println()
		}
	}()
}

func testGoRoutine() {
	ch := make(chan int, 1024)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		var i int
		for {
			select {
			case ch <- i:
			case <-ctx.Done():
				return
			}
			i++
			time.Sleep(50 * time.Millisecond)
		}
	}()
	go func() {
		// deadlock
		defer cancel()
		for {
			select {
			case i := <-ch:
				fmt.Println("index:", i)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func testLargeBuffer() {
	alloc := func(period time.Duration, min, max int) {
		for {
			buf := make([]byte, min+rand.Intn(max)) // #nosec
			init := byte(rand.Int())                // #nosec
			for i := 0; i < len(buf); i++ {
				buf[i] = init
				init++
			}
			fmt.Println("alloc buffer:", len(buf))

			// check memory data after trigger sleep
			raw := sha256.Sum256(buf)
			time.Sleep(250 * time.Millisecond)
			now := sha256.Sum256(buf)
			if raw != now {
				log.Fatalln("memory data is incorrect")
			}
			time.Sleep(period)
		}
	}
	go alloc(100*time.Millisecond, 1, 128)
	go alloc(100*time.Millisecond, 1, 512)
	go alloc(100*time.Millisecond, 256, 1024)
	go alloc(100*time.Millisecond, 512, 1024)
	go alloc(150*time.Millisecond, 1024, 16*1024)
	go alloc(150*time.Millisecond, 4096, 16*1024)
	go alloc(250*time.Millisecond, 16*1024, 512*1024)
	go alloc(250*time.Millisecond, 64*1024, 512*1024)
	go alloc(500*time.Millisecond, 1*1024*1024, 4*1024*1024)
	go alloc(500*time.Millisecond, 2*1024*1024, 4*1024*1024)
}

var (
	webAddr = "127.0.0.1:0"
	webPage = []byte("hello browser!")
)

func testHTTPServer() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	checkError(err)
	webAddr = listener.Addr().String()
	fmt.Println("web server:", webAddr)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(webPage)
	})

	server := http.Server{
		Handler: mux,
	} // #nosec
	go func() {
		err := server.Serve(listener)
		checkError(err)
	}()
}

func testHTTPClient() {
	go func() {
		client := http.Client{}
		for {
			func() {
				resp, err := client.Get(fmt.Sprintf("http://%s/", webAddr))
				if err != nil {
					return
				}
				defer func() { _ = resp.Body.Close() }()
				data, err := io.ReadAll(resp.Body)
				if err != nil {
					return
				}
				if !bytes.Equal(webPage, data) {
					log.Fatalln("incorrect web page data")
				}
				fmt.Println("http client keep alive")
				client.CloseIdleConnections()
			}()
			time.Sleep(1 + time.Duration(rand.Intn(250))*time.Millisecond) // #nosec
		}
	}()
}

func testWatchdog() {
	if GleamRT == nil {
		return
	}

	var (
		Kick      = GleamRT.MustFindProc("WD_Kick")
		Enable    = GleamRT.MustFindProc("WD_Enable")
		Disable   = GleamRT.MustFindProc("WD_Disable")
		IsEnabled = GleamRT.MustFindProc("WD_IsEnabled")
	)

	ret, _, _ := IsEnabled.Call()
	if ret == 1 {
		fmt.Println("========watchdog is already enabled========")
	} else {
		ret, _, _ = Enable.Call()
		if ret != noError {
			log.Printf("[warning] failed to enable watchdog: 0x%X\n", ret)
			return
		}
		fmt.Println("========watchdog is enabled========")
	}

	go func() {
		for i := 0; i < 100; i++ {
			ret, _, _ = Kick.Call()
			if ret != noError {
				log.Fatalf("failed to kick watchdog: 0x%X\n", ret)
			}
			time.Sleep(time.Second)
		}
		ret, _, _ = Disable.Call()
		if ret != noError {
			log.Fatalf("failed to disable watchdog: 0x%X\n", ret)
		}
		ret, _, _ = Enable.Call()
		if ret != noError {
			log.Fatalf("failed to enable watchdog: 0x%X\n", ret)
		}
	}()
}

func testGetMetric() {
	if GleamRT == nil {
		return
	}

	GetMetrics := GleamRT.MustFindProc("GetMetrics")
	go func() {
		for {
			metrics := gleamrt.Metrics{}
			ret, _, _ := GetMetrics.Call(uintptr(unsafe.Pointer(&metrics)))
			if ret != noError {
				log.Fatalf("failed to get runtime metrics: 0x%X\n", ret)
			}
			spew.Dump(metrics)
			time.Sleep(3 * time.Second)
		}
	}()
}

func kernel32Sleep() {
	go func() {
		var counter int
		for {
			// wait go routine run other test
			time.Sleep(1 + time.Duration(rand.Intn(1000))*time.Millisecond) // #nosec
			// trigger Gleam-RT SleepHR
			fmt.Println("call kernel32.Sleep [hooked]")
			now := time.Now()
			ret, _, _ := procSleep.Call(1 + uintptr(rand.Intn(1000))) // #nosec
			if ret != noError {
				log.Fatalf("occurred error when sleep: 0x%X\n", ret)
			}
			counter++
			fmt.Println("Sleep:", time.Since(now), "Times:", counter)
			fmt.Println()
		}
	}()
}

func checkError(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
