//go:build windows

package loader

import (
	"bytes"
	"debug/pe"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Instance contains the allocated memory page and pipe.
type Instance struct {
	*PELoaderM

	instAddr uintptr
	instData []byte

	stdInputR  *os.File
	stdInputW  *os.File
	stdOutputR *os.File
	stdOutputW *os.File
	stdErrorR  *os.File
	stdErrorW  *os.File

	sameOutErr bool
	outErrMu   sync.Mutex

	wg sync.WaitGroup
}

// LoadInMemoryEXE is used to load an unmanaged exe image to memory.
func LoadInMemoryEXE(image []byte, opts *Options) (*Instance, error) {
	return loadInstance(image, opts, false)
}

// LoadInMemoryDLL is used to load an unmanaged dll image to memory.
func LoadInMemoryDLL(image []byte, opts *Options) (*Instance, error) {
	return loadInstance(image, opts, true)
}

func loadInstance(image []byte, opts *Options, isDLL bool) (*Instance, error) {
	peFile, err := pe.NewFile(bytes.NewReader(image))
	if err != nil {
		return nil, err
	}
	if isDLL && (peFile.Characteristics&pe.IMAGE_FILE_DLL) == 0 {
		return nil, errors.New("pe image is not a dll")
	}
	var arch string
	switch peFile.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		arch = "386"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		arch = "amd64"
	default:
		return nil, errors.New("unknown pe image architecture type")
	}
	// copy options for overwrite
	if opts == nil {
		opts = new(Options)
	}
	options := *opts
	// process pipe for standard handle
	instance := Instance{}
	err = instance.startPipe(&options)
	if err != nil {
		return nil, fmt.Errorf("failed to start pipe: %s", err)
	}
	// overwrite options for control instance
	options.WaitMain = false
	options.NotStopRuntime = true
	options.Runtime.NotAdjustProtect = true
	options.Runtime.TrackCurrentThread = false
	// create instance
	inst, err := CreateInstance(arch, NewEmbed(image), &options)
	if err != nil {
		return nil, fmt.Errorf("failed to create instance: %s", err)
	}
	// prepare memory page for write instance
	size := uintptr(len(inst))
	mType := uint32(windows.MEM_COMMIT | windows.MEM_RESERVE)
	mProtect := uint32(windows.PAGE_READWRITE)
	instAddr, err := windows.VirtualAlloc(0, size, mType, mProtect)
	if err != nil {
		return nil, fmt.Errorf("failed to alloc memory for instance: %s", err)
	}
	var old uint32
	err = windows.VirtualProtect(instAddr, size, windows.PAGE_EXECUTE_READWRITE, &old)
	if err != nil {
		return nil, fmt.Errorf("failed to change memory protect: %s", err)
	}
	instData := unsafe.Slice((*byte)(unsafe.Pointer(instAddr)), size) // #nosec
	copy(instData, inst)
	// load instance
	ptr, _, err := syscall.SyscallN(instAddr)
	if ptr == null {
		return nil, fmt.Errorf("failed to load instance: 0x%X", err)
	}
	instance.PELoaderM = NewPELoader(ptr)
	instance.instAddr = instAddr
	instance.instData = instData
	return &instance, nil
}

func (inst *Instance) startPipe(options *Options) error {
	if options.IgnoreStdIO {
		return nil
	}
	if options.Stdout != nil && options.Stdout == options.Stderr {
		inst.sameOutErr = true
	}

	return nil
}

func (inst *Instance) startStdinPipe(options *Options) error {
	if options.StdInput != 0 || options.Stdin == nil {
		return nil
	}
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("failed to create pipe for stdin: %s", err)
	}
	options.StdInput = uint64(r.Fd())
	inst.stdInputR = r
	inst.stdInputW = w
	inst.wg.Add(1)
	go func() {
		defer inst.wg.Done()
		_, _ = io.Copy(w, options.Stdin)
	}()
	return nil
}

func (inst *Instance) startStdoutPipe(options *Options) error {
	if options.StdOutput != 0 || options.Stdout == nil {
		return nil
	}
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("failed to create pipe for stdout: %s", err)
	}
	options.StdOutput = uint64(w.Fd())
	inst.stdOutputR = r
	inst.stdOutputW = w
	inst.wg.Add(1)
	go func() {
		defer inst.wg.Done()
		_, _ = io.Copy(options.Stdout, r)
	}()
	return nil
}

func (inst *Instance) startStderrPipe(options *Options) error {
	if options.StdInput != 0 || options.Stdin == nil {
		return nil
	}
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("failed to create pipe for stderr: %s", err)
	}
	options.StdError = uint64(w.Fd())
	inst.stdErrorR = r
	inst.stdErrorW = w
	inst.wg.Add(1)
	go func() {
		defer inst.wg.Done()
		_, _ = io.Copy(options.Stderr, r)
	}()
	return nil
}

// Restart is used to exit image and start image or execute dll_main.
func (inst *Instance) Restart() error {
	err1 := inst.Exit(0)
	var err2 error
	if inst.IsDLL {
		err2 = inst.Execute()
	} else {
		err2 = inst.Start()
	}
	if err2 != nil {
		return err2
	}
	return err1
}

// Free is used to destroy instance and free memory page about it.
func (inst *Instance) Free() error {
	err := inst.Destroy()
	if err != nil {
		return err
	}
	copy(inst.instData, bytes.Repeat([]byte{0}, len(inst.instData)))
	err = windows.VirtualFree(inst.instAddr, 0, windows.MEM_RELEASE)
	if err != nil {
		return err
	}
	return nil
}
