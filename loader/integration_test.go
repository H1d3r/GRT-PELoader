//go:build windows

package loader

import (
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLoadInMemoryEXE(t *testing.T) {
	t.Run("wait exit", func(t *testing.T) {
		var (
			template []byte
			image    []byte
			err      error
		)
		switch runtime.GOARCH {
		case "386":
			template = testLDRx86
			image, err = os.ReadFile("../test/image/x86/rust_msvc.exe")
		case "amd64":
			template = testLDRx64
			image, err = os.ReadFile("../test/image/x64/rust_msvc.exe")
		default:
			t.Fatal("unsupported architecture")
		}
		require.NoError(t, err)

		opts := Options{
			WaitMain: true,
		}
		PELoaderM, err := LoadInMemoryEXE(template, image, &opts)
		require.NoError(t, err)
		require.Nil(t, PELoaderM)
	})

	t.Run("not wait exit", func(t *testing.T) {
		var (
			template []byte
			image    []byte
			err      error
		)
		switch runtime.GOARCH {
		case "386":
			template = testLDRx86
			image, err = os.ReadFile("../test/image/x86/go.exe")
		case "amd64":
			template = testLDRx64
			image, err = os.ReadFile("../test/image/x64/go.exe")
		default:
			t.Fatal("unsupported architecture")
		}
		require.NoError(t, err)

		opts := Options{
			CommandLine: "-kick 20",
			WaitMain:    false,
		}
		PELoaderM, err := LoadInMemoryEXE(template, image, &opts)
		require.NoError(t, err)

		time.Sleep(3 * time.Second)

		err = PELoaderM.Exit(0)
		require.NoError(t, err)
		require.Zero(t, PELoaderM.ExitCode)

		err = PELoaderM.Destroy()
		require.NoError(t, err)
	})

	t.Run("restart", func(t *testing.T) {
		var (
			template []byte
			image    []byte
			err      error
		)
		switch runtime.GOARCH {
		case "386":
			template = testLDRx86
			image, err = os.ReadFile("../test/image/x86/go.exe")
		case "amd64":
			template = testLDRx64
			image, err = os.ReadFile("../test/image/x64/go.exe")
		default:
			t.Fatal("unsupported architecture")
		}
		require.NoError(t, err)

		opts := Options{
			CommandLine: "-kick 20",
			WaitMain:    false,
		}
		PELoaderM, err := LoadInMemoryEXE(template, image, &opts)
		require.NoError(t, err)

		time.Sleep(3 * time.Second)

		err = PELoaderM.Exit(0)
		require.NoError(t, err)
		require.Zero(t, PELoaderM.ExitCode)

		for i := 0; i < 3; i++ {
			err = PELoaderM.Execute()
			require.NoError(t, err)

			time.Sleep(3 * time.Second)

			err = PELoaderM.Exit(1)
			require.NoError(t, err)
			require.Equal(t, uint(1), PELoaderM.ExitCode)
		}

		err = PELoaderM.Destroy()
		require.NoError(t, err)
	})
}

func TestLoadInMemoryDLL(t *testing.T) {

}
