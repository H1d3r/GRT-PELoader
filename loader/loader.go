//go:build windows

package loader

import (
	"fmt"
	"syscall"
	"unsafe"
)

type errno struct {
	method string
	errno  uintptr
}

func (e *errno) Error() string {
	return fmt.Sprintf("PELoaderM.%s return errno: 0x%08X", e.method, e.errno)
}

type PELoaderCfg struct {
	// use custom FindAPI from Gleam-RT for hook.
	FindAPI uintptr

	// PE image memory address.
	Image uintptr

	// for hook GetCommandLineA and GetCommandLineW,
	// if them are NULL, call original GetCommandLine.
	CommandLineA uintptr
	CommandLineW uintptr

	// wait main thread exit if it is an exe image.
	WaitMain bool

	// if failed to load library, can continue it.
	AllowSkipDLL bool

	// set standard handles for hook GetStdHandle,
	// if them are NULL, call original GetStdHandle.
	StdInput  uintptr
	StdOutput uintptr
	StdError  uintptr

	// not erase instructions after call functions about Init or Exit.
	NotEraseInstruction bool

	// adjust current memory page protect.
	NotAdjustProtect bool
}

type PELoaderM struct {
	// absolute memory address about PE entry point.
	EntryPoint uintptr

	// about PE image type and is a managed image.
	IsDLL    bool
	IsDotnet bool

	// main thread return value or argument about call ExitProcess.
	ExitCode uint

	// get export method address if PE image is a DLL.
	getProc uintptr

	// create a thread at EntryPoint, it can call multi times.
	execute uintptr

	// release all resource, it can call multi times.
	exit uintptr

	// destroy all resource about PE loader, it can only call one time.
	destroy uintptr
}

// GetProcAddress is used to get procedure address by name.
func (ldr *PELoaderM) GetProcAddress(name string) (uintptr, error) {
	ptr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0, err
	}
	ret, _, en := syscall.SyscallN(ldr.getProc, uintptr(unsafe.Pointer(ptr)))
	if ret == 0 {
		return 0, &errno{method: "GetProc", errno: uintptr(en)}
	}
	return ret, nil
}

// Execute is used to execute exe or call DllMain with DLL_PROCESS_ATTACH.
// It can call multi times.
func (ldr *PELoaderM) Execute() error {
	ret, _, _ := syscall.SyscallN(ldr.execute)
	if ret != 0 {
		return &errno{method: "Execute", errno: ret}
	}
	return nil
}

// Exit is used to exit exe or call DllMain with DLL_PROCESS_DETACH.
// It can call multi times.
func (ldr *PELoaderM) Exit(code uint) error {
	ret, _, _ := syscall.SyscallN(ldr.exit, uintptr(code))
	if ret != 0 {
		return &errno{method: "Exit", errno: ret}
	}
	return nil
}

// Destroy is used to destroy all resource about PE loader.
// It can only call one time.
func (ldr *PELoaderM) Destroy() error {
	ret, _, _ := syscall.SyscallN(ldr.destroy)
	if ret != 0 {
		return &errno{method: "Destroy", errno: ret}
	}
	return nil
}
