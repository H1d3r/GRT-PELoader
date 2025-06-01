//go:build windows

package loader

import (
	"bytes"
	"debug/pe"
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

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
	// overwrite some options
	if opts == nil {
		opts = new(Options)
	}
	options := *opts
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
	// if wait main, the loader and runtime will be destroyed
	if opts.WaitMain == true {
		return nil, nil
	}
	// copy memory for prevent runtime encrypt memory page when call loader method
	loader := *(NewPELoader(ptr))
	return &loader, nil
}
