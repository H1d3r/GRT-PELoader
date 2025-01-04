package loader

import (
	"os"
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

		embed := NewEmbedPreCompress(compressed, len(image))

		config, err := embed.Encode()
		require.NoError(t, err)
		require.Less(t, len(config), len(image))

		spew.Dump(config)
	})
}
