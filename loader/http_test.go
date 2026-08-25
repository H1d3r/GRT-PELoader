package loader

import (
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

const testURL = "https://github.com/RTS-Framework/GRT-PELoader"

func TestHTTP(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		image := NewHTTP(testURL, nil)

		config, err := image.Encode()
		require.NoError(t, err)

		spew.Dump(config)
	})

	t.Run("with options", func(t *testing.T) {
		headers := make(http.Header)
		headers.Set("Header1", "h1")
		headers.Set("Header2", "h2")
		opts := &HTTPOptions{
			Headers:   headers,
			UserAgent: "ua",
			ProxyURL:  "http://127.0.0.1:8080/",
		}
		image := NewHTTP(testURL, opts)

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

	t.Run("invalid proxy URL", func(t *testing.T) {
		opts := &HTTPOptions{
			ProxyURL: "invalid url",
		}
		image := NewHTTP(testURL, opts)

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

	// start an http server
	path, err := filepath.Abs("../test/image")
	require.NoError(t, err)
	serverMux := http.NewServeMux()
	serverMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Header1") != "h1" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.Header.Get("Header2") != "h2" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.UserAgent() != "ua" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		http.FileServer(http.Dir(path)).ServeHTTP(w, r)
	})
	server := http.Server{
		Handler: serverMux,
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	httpAddr := listener.Addr().String()
	go func() {
		_ = server.Serve(listener)
	}()
	defer func() {
		_ = server.Close()
	}()

	headers := make(http.Header)
	headers.Set("Header1", "h1")
	headers.Set("Header2", "h2")
	opts := &HTTPOptions{
		Headers:   headers,
		UserAgent: "ua",
	}
	opts.Headers.Set("Header1", "h1")

	test := func(url string) {
		for _, item := range testImages {
			URL := fmt.Sprintf(url, httpAddr, item)
			image := NewHTTP(URL, opts)
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
			require.NotEqual(t, uintptr(0), ret, err)
		}
	}

	t.Run("x86", func(t *testing.T) {
		if runtime.GOARCH != "386" {
			return
		}
		test("http://%s/x86/%s")
	})

	t.Run("x64", func(t *testing.T) {
		if runtime.GOARCH != "amd64" {
			return
		}
		test("http://%s/x64/%s")
	})
}
