package loader

import (
	"syscall"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func loadInstance(t *testing.T, inst []byte) uintptr {
	size := uintptr(len(inst))
	mType := uint32(windows.MEM_COMMIT | windows.MEM_RESERVE)
	mProtect := uint32(windows.PAGE_EXECUTE_READWRITE)
	addr, err := windows.VirtualAlloc(0, size, mType, mProtect)
	require.NoError(t, err)
	dst := unsafe.Slice((*byte)(unsafe.Pointer(addr)), size)
	copy(dst, inst)
	return addr
}

// for cross-compile
//
//go:uintptrescapes
func syscallN(trap uintptr, args ...uintptr) (r1, r2 uintptr, err syscall.Errno) {
	return syscall.SyscallN(trap, args...)
}
