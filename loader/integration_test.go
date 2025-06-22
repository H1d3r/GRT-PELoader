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

var (
	testImageGo   []byte
	testImageRust []byte
	testImageCPP  []byte
)

func init() {
	var err error
	switch runtime.GOARCH {
	case "386":
		testImageGo, err = os.ReadFile("../test/image/x86/go.exe")
	case "amd64":
		testImageGo, err = os.ReadFile("../test/image/x64/go.exe")
	}
	if err != nil {
		panic(err)
	}
	switch runtime.GOARCH {
	case "386":
		testImageRust, err = os.ReadFile("../test/image/x86/rust_msvc.exe")
	case "amd64":
		testImageRust, err = os.ReadFile("../test/image/x64/rust_msvc.exe")
	}
	if err != nil {
		panic(err)
	}
	testImageCPP, err = os.ReadFile("C:\\Windows\\System32\\ws2_32.dll")
	if err != nil {
		panic(err)
	}
}

func TestLoadInMemoryEXE(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		opts := Options{
			CommandLine: "-kick 20",
		}
		instance, err := LoadInMemoryEXE(testImageGo, &opts)
		require.NoError(t, err)

		wg := sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(5 * time.Second)
			err := instance.Free()
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
		instance, err := LoadInMemoryEXE(testImageGo, &opts)
		require.NoError(t, err)

		wg := sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(5 * time.Second)
			err := instance.Free()
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
		instance, err := LoadInMemoryEXE(testImageGo, &opts)
		require.NoError(t, err)

		wg := sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(5 * time.Second)
			err := instance.Free()
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
			CommandLine: "-kick 20",
		}
		instance, err := LoadInMemoryEXE(testImageGo, &opts)
		require.NoError(t, err)

		err = instance.Start()
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		err = instance.Free()
		require.NoError(t, err)
	})

	t.Run("exit before start", func(t *testing.T) {
		opts := Options{
			CommandLine: "-kick 20",
		}
		instance, err := LoadInMemoryEXE(testImageGo, &opts)
		require.NoError(t, err)

		err = instance.Exit(0)
		require.NoError(t, err)
		require.Zero(t, instance.ExitCode())

		err = instance.Start()
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		err = instance.Free()
		require.NoError(t, err)
	})

	t.Run("restart", func(t *testing.T) {
		instance, err := LoadInMemoryEXE(testImageRust, nil)
		require.NoError(t, err)

		for i := 0; i < 3; i++ {
			err = instance.Restart()
			require.NoError(t, err)

			time.Sleep(2 * time.Second)

			err = instance.Exit(uint(i) + 123)
			require.NoError(t, err)
			require.Equal(t, uint(i)+123, instance.ExitCode())
		}

		err = instance.Free()
		require.NoError(t, err)
	})
}

func TestLoadInMemoryDLL(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		opts := Options{
			AllowSkipDLL: true,
		}
		instance, err := LoadInMemoryDLL(testImageCPP, &opts)
		require.NoError(t, err)

		err = instance.Run()
		require.NoError(t, err)

		WSAStartup, err := instance.GetProcAddress("WSAStartup")
		require.NoError(t, err)
		require.NotZero(t, WSAStartup)

		err = instance.Free()
		require.NoError(t, err)
	})

	t.Run("restart", func(t *testing.T) {
		opts := Options{
			AllowSkipDLL: true,
		}
		instance, err := LoadInMemoryDLL(testImageCPP, &opts)
		require.NoError(t, err)

		for i := 0; i < 3; i++ {
			err = instance.Restart()
			require.NoError(t, err)

			WSAStartup, err := instance.GetProcAddress("WSAStartup")
			require.NoError(t, err)
			require.NotZero(t, WSAStartup)

			err = instance.Exit(uint(i) + 123)
			require.NoError(t, err)
			require.Equal(t, uint(i)+123, instance.ExitCode())
		}

		err = instance.Free()
		require.NoError(t, err)
	})
}
