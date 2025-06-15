//go:build windows

package loader

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var testImage []byte

func init() {
	var err error
	switch runtime.GOARCH {
	case "386":
		testImage, err = os.ReadFile("../test/image/x86/go.exe")
	case "amd64":
		testImage, err = os.ReadFile("../test/image/x64/go.exe")
	default:
		panic("unsupported architecture")
	}
	if err != nil {
		panic(err)
	}
}

func TestLoadInMemoryEXE(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		opts := Options{
			CommandLine: "-kick 20",
		}
		instance, err := LoadInMemoryEXE(testImage, &opts)
		require.NoError(t, err)

		wg := sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(5 * time.Second)
			err = instance.Free()
			require.NoError(t, err)
		}()

		err = instance.Run()
		require.NoError(t, err)

		wg.Wait()
	})

	t.Run("with different output error", func(t *testing.T) {
		stdin := new(bytes.Buffer)
		stdout := new(bytes.Buffer)
		stderr := new(bytes.Buffer)

		opts := Options{
			CommandLine: "-kick 20",

			Stdin:  stdin,
			Stdout: stdout,
			Stderr: stderr,
		}
		instance, err := LoadInMemoryEXE(testImage, &opts)
		require.NoError(t, err)

		wg := sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(5 * time.Second)
			err = instance.Free()
			require.NoError(t, err)
		}()

		err = instance.Run()
		require.NoError(t, err)

		fmt.Println("stdout:\n", stdout)
		fmt.Println("stderr:\n", stderr)

		wg.Wait()
	})

	t.Run("with same output error", func(t *testing.T) {
		stdin := new(bytes.Buffer)
		output := new(bytes.Buffer)

		opts := Options{
			CommandLine: "-kick 20",

			Stdin:  stdin,
			Stdout: output,
			Stderr: output,
		}
		instance, err := LoadInMemoryEXE(testImage, &opts)
		require.NoError(t, err)

		wg := sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(5 * time.Second)
			err = instance.Free()
			require.NoError(t, err)
		}()

		err = instance.Run()
		require.NoError(t, err)

		fmt.Println("stdout:\n", output)
		fmt.Println("stderr:\n", output)

		wg.Wait()
	})

	t.Run("not wait exit", func(t *testing.T) {
		opts := Options{
			CommandLine:    "-kick 20",
			WaitMain:       false,
			NotStopRuntime: true,
		}
		PELoaderM, err := LoadInMemoryEXE(testImage, &opts)
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
		PELoaderM, err := LoadInMemoryEXE(testImage, &opts)
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		err = PELoaderM.Exit(0)
		require.NoError(t, err)
		require.Zero(t, PELoaderM.ExitCode())

		time.Sleep(time.Hour)

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
