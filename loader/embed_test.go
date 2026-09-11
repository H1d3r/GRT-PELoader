package loader

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/For-ACGN/LZSS"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestEmbed(t *testing.T) {
	image, err := os.ReadFile("testdata/executable.dat")
	require.NoError(t, err)

	t.Run("common", func(t *testing.T) {
		embed := NewEmbed(image, nil)

		config, err := embed.Encode()
		require.NoError(t, err)
		require.Greater(t, len(config), len(image))

		spew.Dump(config)
	})

	t.Run("invalid PE image", func(t *testing.T) {
		invalid := []byte{0x00, 0x01}
		embed := NewEmbed(invalid, nil)

		config, err := embed.Encode()
		require.EqualError(t, err, "invalid PE image: EOF")
		require.Nil(t, config)
	})

	t.Run("mode", func(t *testing.T) {
		embed := NewEmbed(image, nil)
		require.Equal(t, ModeEmbed, embed.Mode())
	})
}

func TestEmbedCompress(t *testing.T) {
	image, err := os.ReadFile("testdata/executable.dat")
	require.NoError(t, err)

	t.Run("common", func(t *testing.T) {
		opts := EmbedOptions{
			Compress:   true,
			WindowSize: lzss.MaximumWindowSize,
			ChainLen:   lzss.DefaultChainLen,
		}
		embed := NewEmbed(image, &opts)

		config, err := embed.Encode()
		require.NoError(t, err)
		require.Less(t, len(config), len(image))

		spew.Dump(config)
	})

	t.Run("invalid window size", func(t *testing.T) {
		opts := EmbedOptions{
			Compress:   true,
			WindowSize: 40960,
			ChainLen:   lzss.DefaultChainLen,
		}
		embed := NewEmbed(image, &opts)

		config, err := embed.Encode()
		errStr := "failed to compress PE image: invalid window size"
		require.EqualError(t, err, errStr)
		require.Nil(t, config)
	})
}

func TestEmbedPreCompressed(t *testing.T) {
	image, err := os.ReadFile("testdata/executable.dat")
	require.NoError(t, err)

	t.Run("common", func(t *testing.T) {
		windowSize := lzss.MaximumWindowSize
		chainLen := lzss.DefaultChainLen
		compressed, err := lzss.Compress(image, windowSize, chainLen)
		require.NoError(t, err)

		opts := EmbedOptions{
			PreCompressed: true,
		}
		embed := NewEmbed(compressed, &opts)

		config, err := embed.Encode()
		require.NoError(t, err)
		require.Less(t, len(config), len(image))

		spew.Dump(config)
	})

	t.Run("invalid compressed data", func(t *testing.T) {
		invalid := []byte{0x80, 0x00}
		opts := EmbedOptions{
			PreCompressed: true,
		}
		embed := NewEmbed(invalid, &opts)

		config, err := embed.Encode()
		errStr := "invalid precompressed PE image: truncated match reference"
		require.EqualError(t, err, errStr)
		require.Nil(t, config)
	})
}

func TestEmbedInstance(t *testing.T) {
	if runtime.GOOS != "windows" {
		return
	}

	test := func(dir string) {
		for _, item := range testImages {
			path := filepath.Join(dir, item)
			image, err := os.ReadFile(path)
			require.NoError(t, err)

			windowSize := lzss.MaximumWindowSize
			chainLen := lzss.DefaultChainLen
			preCompressed, err := lzss.Compress(image, windowSize, chainLen)
			require.NoError(t, err)

			opts := &EmbedOptions{
				Compress: false,
			}
			embed1 := NewEmbed(image, opts)

			opts = &EmbedOptions{
				Compress:   true,
				WindowSize: lzss.MaximumWindowSize,
				ChainLen:   lzss.DefaultChainLen,
			}
			embed2 := NewEmbed(image, opts)

			opts = &EmbedOptions{
				PreCompressed: true,
			}
			embed3 := NewEmbed(preCompressed, opts)

			for _, img := range []Image{
				embed1, embed2, embed3,
			} {
				opts := &Options{
					ImageName:    "test.exe",
					CommandLine:  "-p1 123 -p2 \"hello\"",
					WaitMain:     true,
					AllowSkipDLL: true,
				}

				inst, err := CreateInstance(runtime.GOARCH, img, opts)
				require.NoError(t, err)

				addr := loadInstance(t, inst)
				ret, _, _ := syscallN(addr, 0)
				require.Equal(t, uintptr(1), ret, err)
			}
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
