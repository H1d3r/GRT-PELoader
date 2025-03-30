package loader

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	testTplX86 []byte // TODO rename
	testTplX64 []byte // TODO rename
)

func init() {
	var err error
	testTplX86, err = os.ReadFile("../dist/PELoader_x86.bin")
	if err != nil {
		panic(err)
	}
	testTplX64, err = os.ReadFile("../dist/PELoader_x64.bin")
	if err != nil {
		panic(err)
	}
}

var images = []struct {
	path string
	wait bool
}{
	{"go.exe", false},
	{"rust_msvc.exe", true},
	{"rust_gnu.exe", true},
	{"ucrtbase_main.exe", true},
	{"ucrtbase_wmain.exe", true},
}

func TestCreateInstance(t *testing.T) {
	file := NewFile(testFilePath)

	t.Run("x86", func(t *testing.T) {
		inst, err := CreateInstance(testTplX86, 32, file, nil)
		require.NoError(t, err)
		require.NotNil(t, inst)
	})

	t.Run("x64", func(t *testing.T) {
		inst, err := CreateInstance(testTplX64, 64, file, nil)
		require.NoError(t, err)
		require.NotNil(t, inst)
	})

	t.Run("with command line", func(t *testing.T) {
		opts := Options{
			CommandLine: "-p1 123 -p2 \"hello\"",
		}

		inst, err := CreateInstance(testTplX86, 32, file, &opts)
		require.NoError(t, err)
		require.NotNil(t, inst)
	})

	t.Run("with program name", func(t *testing.T) {
		opts := Options{
			ImageName:   "test program.exe",
			CommandLine: "-p1 123 -p2 \"hello\"",
		}

		inst, err := CreateInstance(testTplX86, 32, file, &opts)
		require.NoError(t, err)
		require.NotNil(t, inst)
	})

	t.Run("with wait main", func(t *testing.T) {
		opts := Options{
			WaitMain: true,
		}

		inst, err := CreateInstance(testTplX86, 32, file, &opts)
		require.NoError(t, err)
		require.NotNil(t, inst)
	})

	t.Run("with allow skip dll", func(t *testing.T) {
		opts := Options{
			AllowSkipDLL: true,
		}

		inst, err := CreateInstance(testTplX86, 32, file, &opts)
		require.NoError(t, err)
		require.NotNil(t, inst)
	})

	t.Run("invalid image config", func(t *testing.T) {
		embed := NewEmbed([]byte{0x00})

		inst, err := CreateInstance(testTplX86, 32, embed, nil)
		errStr := "invalid embed mode config: invalid PE image: EOF"
		require.EqualError(t, err, errStr)
		require.Nil(t, inst)
	})

	t.Run("invalid architecture", func(t *testing.T) {
		inst, err := CreateInstance(testTplX86, 12, file, nil)
		require.EqualError(t, err, "invalid architecture: 12")
		require.Nil(t, inst)
	})
}
