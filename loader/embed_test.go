package loader

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/For-ACGN/LZSS"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestEmbed(t *testing.T) {
	image, err := os.ReadFile("testdata/executable.dat")
	require.NoError(t, err)

	t.Run("common", func(t *testing.T) {
		embed := NewEmbed(image)

		config, err := embed.Encode()
		require.NoError(t, err)
		require.Greater(t, len(config), len(image))

		spew.Dump(config)
	})

	t.Run("invalid PE image", func(t *testing.T) {
		embed := NewEmbed([]byte{0x00, 0x01})

		config, err := embed.Encode()
		require.EqualError(t, err, "invalid PE image: EOF")
		require.Nil(t, config)
	})

	t.Run("mode", func(t *testing.T) {
		embed := NewEmbed(image)
		require.Equal(t, ModeEmbed, embed.Mode())
	})
}

func TestEmbedCompress(t *testing.T) {
	image, err := os.ReadFile("testdata/executable.dat")
	require.NoError(t, err)

	t.Run("common", func(t *testing.T) {
		embed := NewEmbedCompress(image, 4096)

		config, err := embed.Encode()
		require.NoError(t, err)
		require.Less(t, len(config), len(image))

		spew.Dump(config)
	})

	t.Run("invalid window size", func(t *testing.T) {
		embed := NewEmbedCompress(image, 40960)

		config, err := embed.Encode()
		errStr := "failed to compress PE image: invalid window size"
		require.EqualError(t, err, errStr)
		require.Nil(t, config)
	})
}

func TestEmbedPreCompress(t *testing.T) {
	image, err := os.ReadFile("testdata/executable.dat")
	require.NoError(t, err)

	t.Run("common", func(t *testing.T) {
		compressed, err := lzss.Compress(image, 4096)
		require.NoError(t, err)

		embed := NewEmbedPreCompress(compressed)

		config, err := embed.Encode()
		require.NoError(t, err)
		require.Less(t, len(config), len(image))

		spew.Dump(config)
	})
}

func TestEmbedInstance(t *testing.T) {
	if runtime.GOOS != "windows" {
		return
	}

	wg := sync.WaitGroup{}
	t.Run("x86", func(t *testing.T) {
		if runtime.GOARCH != "386" {
			return
		}

		for _, item := range images {
			path := filepath.Join("../test/image/x86", item.path)
			image, err := os.ReadFile(path)
			require.NoError(t, err)
			opts := &Options{
				ImageName:    "test.exe",
				CommandLine:  "-p1 123 -p2 \"hello\"",
				WaitMain:     item.wait,
				AllowSkipDLL: true,
			}

			preCompressed, err := lzss.Compress(image, 2048)
			require.NoError(t, err)
			embed1 := NewEmbed(image)
			embed2 := NewEmbedCompress(image, 2048)
			embed3 := NewEmbedPreCompress(preCompressed)

			for _, img := range []Image{
				embed1, embed2, embed3,
			} {
				wg.Add(1)
				go func(img Image) {
					defer wg.Done()
					inst, err := CreateInstance("386", img, opts)
					require.NoError(t, err)

					addr := loadShellcode(t, inst)
					ret, _, _ := syscallN(addr)
					require.NotEqual(t, uintptr(0), ret)
				}(img)
			}
		}
	})

	t.Run("x64", func(t *testing.T) {
		if runtime.GOARCH != "amd64" {
			return
		}

		for _, item := range images {
			path := filepath.Join("../test/image/x64", item.path)
			image, err := os.ReadFile(path)
			require.NoError(t, err)
			opts := &Options{
				ImageName:    "test.exe",
				CommandLine:  "-p1 123 -p2 \"hello\"",
				WaitMain:     item.wait,
				AllowSkipDLL: true,
			}

			preCompressed, err := lzss.Compress(image, 2048)
			require.NoError(t, err)
			embed1 := NewEmbed(image)
			embed2 := NewEmbedCompress(image, 2048)
			embed3 := NewEmbedPreCompress(preCompressed)

			for _, img := range []Image{
				embed1, embed2, embed3,
			} {
				wg.Add(1)
				go func(img Image) {
					defer wg.Done()
					inst, err := CreateInstance("amd64", img, opts)
					require.NoError(t, err)

					addr := loadShellcode(t, inst)
					ret, _, _ := syscallN(addr)
					require.NotEqual(t, uintptr(0), ret)
				}(img)
			}
		}
	})
	wg.Wait()
}
