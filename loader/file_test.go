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
	if runtime.GOOS != "windows" {
		return
	}

	test := func(dir string) {
		for _, item := range testImages {
			path, err := filepath.Abs(filepath.Join(dir, item))
			require.NoError(t, err)
			image := NewFile(path)
			opts := &Options{
				ImageName:    "test.exe",
				CommandLine:  "-p1 123 -p2 \"hello\"",
				WaitMain:     true,
				AllowSkipDLL: true,
			}

			inst, err := CreateInstance(runtime.GOARCH, image, opts)
			require.NoError(t, err)

			addr := loadInstance(t, inst)
			ret, _, _ := syscallN(addr, 0)
			require.Equal(t, uintptr(1), ret, err)
		}
	}

	t.Run("x86", func(t *testing.T) {
		if runtime.GOARCH != "386" {
			return
		}
		test("../test/image/x86")
	})

	t.Run("x64", func(t *testing.T) {
		if runtime.GOARCH != "amd64" {
			return
		}
		test("../test/image/x64")
	})
}
