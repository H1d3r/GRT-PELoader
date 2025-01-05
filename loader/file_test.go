package loader

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

const testFilePath = "C:\\Windows\\System32\\cmd.exe"

func TestFile(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		image := NewFile(testFilePath)

		config, err := image.Encode()
		require.NoError(t, err)

		spew.Dump(config)
	})

	t.Run("mode", func(t *testing.T) {
		image := NewFile(testFilePath)
		require.Equal(t, ModeFile, image.Mode())
	})
}

func TestFileInstance(t *testing.T) {
	opts := &Options{
		ImageName:    "test.exe",
		CommandLine:  "-p1 123 -p2 \"hello\"",
		WaitMain:     true,
		AllowSkipDLL: true,
	}

	t.Run("x86", func(t *testing.T) {
		if runtime.GOOS != "windows" || runtime.GOARCH != "386" {
			return
		}

		for _, item := range images {
			path, err := filepath.Abs(filepath.Join("../test/image/x86", item.path))
			require.NoError(t, err)
			image := NewFile(path)
			opts.WaitMain = item.wait

			inst, err := CreateInstance(testTplX86, 32, image, opts)
			require.NoError(t, err)

			addr := loadShellcode(t, inst)
			ret, _, _ := syscallN(addr)
			require.NotEqual(t, uintptr(0), ret)
		}
	})

	t.Run("x64", func(t *testing.T) {
		if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
			return
		}

		for _, item := range images {
			path, err := filepath.Abs(filepath.Join("../test/image/x64", item.path))
			require.NoError(t, err)
			image := NewFile(path)
			opts.WaitMain = item.wait

			inst, err := CreateInstance(testTplX64, 64, image, opts)
			require.NoError(t, err)

			addr := loadShellcode(t, inst)
			ret, _, _ := syscallN(addr)
			require.NotEqual(t, uintptr(0), ret)
		}
	})
}
