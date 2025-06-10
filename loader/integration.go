//go:build windows

package loader

import (
	"bytes"
	"debug/pe"
	"errors"
	"fmt"
	"io"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Instance contains the allocated memory page and pipe.
type Instance struct {
	instAddress uintptr

	stdInputFile  io.WriteCloser
	stdOutputFile io.ReadCloser
	stdErrorFile  io.ReadCloser

	PELoaderM
}

func (inst *Instance) Restart() error {
	return nil
}

// Free is used to destroy instance and free memory page about it.
func (inst *Instance) Free() error {
	err := inst.Destroy()
	if err != nil {
		return err
	}
	err = windows.VirtualFree(inst.instAddress, 0, windows.MEM_RELEASE)
	if err != nil {
		return err
	}
	return nil
}

// LoadInMemoryEXE is used to load an unmanaged exe image to memory.
// If Options.WaitMain is true, the returned PELoaderM is always nil.
func LoadInMemoryEXE(template, image []byte, opts *Options) (*PELoaderM, error) {
	return loadInstance(template, image, opts, false)
}

// LoadInMemoryDLL is used to load an unmanaged dll image to memory.
func LoadInMemoryDLL(template, image []byte, opts *Options) (*PELoaderM, error) {
	return loadInstance(template, image, opts, true)
}

func loadInstance(template, image []byte, opts *Options, isDLL bool) (*PELoaderM, error) {
	peFile, err := pe.NewFile(bytes.NewReader(image))
	if err != nil {
		return nil, err
	}
	if isDLL && (peFile.Characteristics&pe.IMAGE_FILE_DLL) == 0 {
		return nil, errors.New("pe image is not a dll")
	}
	var arch int
	switch peFile.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		arch = 64
	case pe.IMAGE_FILE_MACHINE_I386:
		arch = 32
	default:
		return nil, errors.New("unknown pe image architecture type")
	}
	if opts == nil {
		opts = new(Options)
	}
	// process pipe
	// var (
	// 	stdInput  = opts.StdInput
	// 	stdOutput = opts.StdOutput
	// 	stdError  = opts.StdError
	// )
	// var (
	// 	stdInputFile  io.WriteCloser
	// 	stdOutputFile io.ReadCloser
	// 	stdErrorFile  io.ReadCloser
	// )
	// if opts.StdInputFile != nil {
	// 	r, w, err := os.Pipe()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	stdInput = uint64(r.Fd())
	// 	stdInputFile = w
	// }
	// if opts.StdOutputFile != nil {
	// 	r, w, err := os.Pipe()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	stdOutput = uint64(w.Fd())
	// 	stdOutputFile = r
	// }
	// if opts.StdErrorFile != nil {
	// 	r, w, err := os.Pipe()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	stdError = uint64(w.Fd())
	// 	stdErrorFile = r
	// }
	// overwrite options for control instance
	options := *opts
	options.WaitMain = false

	// options.StdInput
	// options.StdOutput
	// options.StdError

	options.NotStopRuntime = true
	options.Runtime.NotAdjustProtect = true
	options.Runtime.TrackCurrentThread = false
	// create instance
	instance, err := CreateInstance(template, arch, NewEmbed(image), &options)
	if err != nil {
		return nil, fmt.Errorf("failed to create instance: %s", err)
	}
	// prepare memory page for write instance
	size := uintptr(len(instance))
	mType := uint32(windows.MEM_COMMIT | windows.MEM_RESERVE)
	mProtect := uint32(windows.PAGE_READWRITE)
	scAddr, err := windows.VirtualAlloc(0, size, mType, mProtect)
	if err != nil {
		return nil, fmt.Errorf("failed to alloc memory for instance: %s", err)
	}
	var old uint32
	err = windows.VirtualProtect(scAddr, size, windows.PAGE_EXECUTE_READWRITE, &old)
	if err != nil {
		return nil, fmt.Errorf("failed to change memory protect: %s", err)
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(scAddr)), size) // #nosec
	copy(dst, instance)
	// load instance
	ptr, _, err := syscall.SyscallN(scAddr)
	if ptr == null {
		return nil, fmt.Errorf("failed to load instance: 0x%X", err)
	}
	return NewPELoader(ptr), nil
}
