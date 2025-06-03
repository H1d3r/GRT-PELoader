//go:build windows

package loader

import (
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var (
	testTemplate []byte
	testImage    []byte
)

func init() {
	var err error
	switch runtime.GOARCH {
	case "386":
		testTemplate = testLDRx86
		testImage, err = os.ReadFile("../test/image/x86/rust_msvc.exe")
	case "amd64":
		testTemplate = testLDRx64
		testImage, err = os.ReadFile("../test/image/x64/rust_msvc.exe")
	default:
		panic("unsupported architecture")
	}
	if err != nil {
		panic(err)
	}
}

func TestLoadInMemoryEXE(t *testing.T) {
	t.Run("wait exit", func(t *testing.T) {
		opts := Options{
			WaitMain:       true,
			NotStopRuntime: false,
		}
		PELoaderM, err := LoadInMemoryEXE(testTemplate, testImage, &opts)
		require.NoError(t, err)
		require.Nil(t, PELoaderM)
	})

	t.Run("not wait exit", func(t *testing.T) {
		opts := Options{
			CommandLine:    "-kick 20",
			WaitMain:       false,
			NotStopRuntime: true,
		}
		PELoaderM, err := LoadInMemoryEXE(testTemplate, testImage, &opts)
		require.NoError(t, err)

		time.Sleep(4 * time.Second)

		err = PELoaderM.Exit(0)
		require.NoError(t, err)
		require.Zero(t, PELoaderM.ExitCode())

		err = PELoaderM.Execute()
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		err = PELoaderM.Destroy()
		require.NoError(t, err)
	})

	t.Run("restart", func(t *testing.T) {
		opts := Options{
			CommandLine:    "-kick 20",
			WaitMain:       false,
			NotStopRuntime: true,
		}
		PELoaderM, err := LoadInMemoryEXE(testTemplate, testImage, &opts)
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		err = PELoaderM.Exit(0)
		require.NoError(t, err)
		require.Zero(t, PELoaderM.ExitCode())

		for i := 0; i < 3; i++ {
			err = PELoaderM.Execute()
			require.NoError(t, err)

			time.Sleep(2 * time.Second)

			err = PELoaderM.Exit(uint(i) + 123)
			require.NoError(t, err)
			require.Equal(t, uint(i)+123, PELoaderM.ExitCode())
		}

		err = PELoaderM.Destroy()
		require.NoError(t, err)
	})
}

func TestLoadInMemoryDLL(t *testing.T) {

}
