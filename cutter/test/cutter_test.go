//go:build windows

package cutter

import (
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/RSSU-Shellcode/Gleam-RT/runtime"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/RSSU-Shellcode/GRT-PELoader/loader"
)

var (
	testLDRx86 []byte
	testLDRx64 []byte
)

func init() {
	var err error
	testLDRx86, err = os.ReadFile("../../dist/trim/PELoader_x86.bin")
	if err != nil {
		panic(err)
	}
	testLDRx64, err = os.ReadFile("../../dist/trim/PELoader_x64.bin")
	if err != nil {
		panic(err)
	}
}

func TestTrimmed(t *testing.T) {
	// process Gleam-RT shellcode data
	var (
		ldr  []byte
		data []byte
		err  error
	)
	switch runtime.GOARCH {
	case "386":
		ldr = testLDRx86
		data, err = os.ReadFile("../../asm/inst/runtime_x86.inst")
	case "amd64":
		ldr = testLDRx64
		data, err = os.ReadFile("../../asm/inst/runtime_x64.inst")
	default:
		t.Fatal("unsupported architecture")
	}
	require.NoError(t, err)
	s := string(data)
	s = strings.ReplaceAll(s, ",", "")
	s = strings.ReplaceAll(s, " 0", "")
	s = strings.ReplaceAll(s, "db", "")
	s = strings.ReplaceAll(s, "h", "")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\r\n", "")
	rt, err := hex.DecodeString(s)
	require.NoError(t, err)

	t.Run("exe", func(t *testing.T) {
		// initialize Gleam-RT
		addr := loadShellcode(t, rt)
		fmt.Printf("Runtime: 0x%X\n", addr)
		RuntimeM, err := gleamrt.InitRuntime(addr, nil)
		require.NoError(t, err)

		// read pe data
		var pe []byte
		switch runtime.GOARCH {
		case "386":
			pe, err = os.ReadFile("../../test/image/x86/rust_msvc.exe")
		case "amd64":
			pe, err = os.ReadFile("../../test/image/x64/rust_msvc.exe")
		}
		require.NoError(t, err)
		config := loader.Config{
			FindAPI:  RuntimeM.HashAPI.FindAPI,
			Image:    (uintptr)(unsafe.Pointer(&pe[0])),
			WaitMain: true,
		}

		// initialize PELoader
		addr = loadShellcode(t, ldr)
		fmt.Printf("PE Loader: 0x%X\n", addr)
		PELoaderM, err := loader.InitPELoader(addr, RuntimeM, &config)
		require.NoError(t, err)

		err = PELoaderM.Execute()
		require.NoError(t, err)

		err = RuntimeM.Exit()
		require.NoError(t, err)
	})

	t.Run("dll", func(t *testing.T) {
		// initialize Gleam-RT
		addr := loadShellcode(t, rt)
		fmt.Printf("Runtime: 0x%X\n", addr)
		RuntimeM, err := gleamrt.InitRuntime(addr, nil)
		require.NoError(t, err)

		// read pe data
		pe, err := os.ReadFile("C:\\Windows\\System32\\ws2_32.dll")
		require.NoError(t, err)
		config := loader.Config{
			FindAPI:      RuntimeM.HashAPI.FindAPI,
			Image:        (uintptr)(unsafe.Pointer(&pe[0])),
			AllowSkipDLL: true,
		}

		// initialize PELoader
		addr = loadShellcode(t, ldr)
		fmt.Printf("PE Loader: 0x%X\n", addr)
		PELoaderM, err := loader.InitPELoader(addr, RuntimeM, &config)
		require.NoError(t, err)

		// call DllMain DLL_PROCESS_ATTACH
		err = PELoaderM.Execute()
		require.NoError(t, err)

		proc, err := PELoaderM.GetProcAddress("connect")
		require.NoError(t, err)
		fmt.Printf("ws2_32.connect: 0x%X\n", proc)

		// call DllMain DLL_PROCESS_DETACH
		err = PELoaderM.Exit(0)
		require.NoError(t, err)

		err = PELoaderM.Destroy()
		require.NoError(t, err)

		err = RuntimeM.Exit()
		require.NoError(t, err)
	})
}

func loadShellcode(t *testing.T, sc []byte) uintptr {
	size := uintptr(len(sc))
	mType := uint32(windows.MEM_COMMIT | windows.MEM_RESERVE)
	mProtect := uint32(windows.PAGE_EXECUTE_READWRITE)
	scAddr, err := windows.VirtualAlloc(0, size, mType, mProtect)
	require.NoError(t, err)
	dst := unsafe.Slice((*byte)(unsafe.Pointer(scAddr)), size)
	copy(dst, sc)
	return scAddr
}
