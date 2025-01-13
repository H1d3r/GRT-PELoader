package loader

import (
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

const testURL = "https://github.com/RSSU-Shellcode/GRT-PELoader"

func TestHTTP(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		image := NewHTTP(testURL, nil)

		config, err := image.Encode()
		require.NoError(t, err)

		spew.Dump(config)
	})

	t.Run("invalid URL", func(t *testing.T) {
		image := NewHTTP("invalid url", nil)

		config, err := image.Encode()
		errStr := "parse \"invalid url\": invalid URI for request"
		require.EqualError(t, err, errStr)
		require.Nil(t, config)
	})

	t.Run("mode", func(t *testing.T) {
		image := NewHTTP(testURL, nil)
		require.Equal(t, ModeHTTP, image.Mode())
	})
}

func TestHTTPInstance(t *testing.T) {
	if runtime.GOOS != "windows" {
		return
	}

	// start a http server
	path, err := filepath.Abs("../test/image")
	require.NoError(t, err)
	server := http.Server{
		Handler: http.FileServer(http.Dir(path)),
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	httpAddr := listener.Addr().String()
	go func() {
		err = server.Serve(listener)
		require.NoError(t, err)
	}()

	wg := sync.WaitGroup{}
	t.Run("x86", func(t *testing.T) {
		if runtime.GOARCH != "386" {
			return
		}

		for _, item := range images {
			URL := fmt.Sprintf("http://%s/x86/%s", httpAddr, item.path)
			image := NewHTTP(URL, nil)
			opts := &Options{
				ImageName:    "test.exe",
				CommandLine:  "-p1 123 -p2 \"hello\"",
				WaitMain:     item.wait,
				AllowSkipDLL: true,
			}

			wg.Add(1)
			go func() {
				defer wg.Done()
				inst, err := CreateInstance(testTplX86, 32, image, opts)
				require.NoError(t, err)

				addr := loadShellcode(t, inst)
				ret, _, _ := syscallN(addr)
				require.NotEqual(t, uintptr(0), ret)
			}()
		}
	})

	t.Run("x64", func(t *testing.T) {
		if runtime.GOARCH != "amd64" {
			return
		}

		for _, item := range images {
			URL := fmt.Sprintf("http://%s/x64/%s", httpAddr, item.path)
			image := NewHTTP(URL, nil)
			opts := &Options{
				ImageName:    "test.exe",
				CommandLine:  "-p1 123 -p2 \"hello\"",
				WaitMain:     item.wait,
				AllowSkipDLL: true,
			}

			wg.Add(1)
			go func() {
				defer wg.Done()
				inst, err := CreateInstance(testTplX64, 64, image, opts)
				require.NoError(t, err)

				addr := loadShellcode(t, inst)
				ret, _, _ := syscallN(addr)
				require.NotEqual(t, uintptr(0), ret)
			}()
		}
	})
	wg.Wait()
}
