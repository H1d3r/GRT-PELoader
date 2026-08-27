package loader

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/RTS-Framework/GRT-Develop/argument"
)

var testImages = []string{
	"rust_msvc.exe",
	"rust_gnu.exe",
	"ucrtbase_main.exe",
	"ucrtbase_wmain.exe",
}

func TestCreateInstance(t *testing.T) {
	image := NewFile(testFilePath)

	t.Run("x86", func(t *testing.T) {
		inst, err := CreateInstance("386", image, nil)
		require.NoError(t, err)
		require.NotNil(t, inst)
	})

	t.Run("x64", func(t *testing.T) {
		inst, err := CreateInstance("amd64", image, nil)
		require.NoError(t, err)
		require.NotNil(t, inst)
	})

	t.Run("custom template", func(t *testing.T) {
		template, err := os.ReadFile("../dist/standard/PELoader_x86.bin")
		require.NoError(t, err)
		opts := Options{
			Template: template,
		}

		inst, err := CreateInstance("386", image, &opts)
		require.NoError(t, err)
		require.NotNil(t, inst)
	})

	t.Run("ignore instantiate options", func(t *testing.T) {
		template, err := os.ReadFile("../dist/pipeline/PELoader_x86.bin")
		require.NoError(t, err)
		opts := Options{
			Template:       template,
			IgnoreInstOpts: true,
		}

		inst, err := CreateInstance("386", image, &opts)
		require.NoError(t, err)
		require.NotNil(t, inst)
	})

	t.Run("with command line", func(t *testing.T) {
		opts := Options{
			CommandLine: "-p1 123 -p2 \"hello\"",
		}

		inst, err := CreateInstance("386", image, &opts)
		require.NoError(t, err)
		require.NotNil(t, inst)
	})

	t.Run("with program name", func(t *testing.T) {
		opts := Options{
			ImageName:   "test program.exe",
			CommandLine: "-p1 123 -p2 \"hello\"",
		}

		inst, err := CreateInstance("386", image, &opts)
		require.NoError(t, err)
		require.NotNil(t, inst)
	})

	t.Run("with wait main", func(t *testing.T) {
		opts := Options{
			WaitMain: true,
		}

		inst, err := CreateInstance("386", image, &opts)
		require.NoError(t, err)
		require.NotNil(t, inst)
	})

	t.Run("with allow skip dll", func(t *testing.T) {
		opts := Options{
			AllowSkipDLL: true,
		}

		inst, err := CreateInstance("386", image, &opts)
		require.NoError(t, err)
		require.NotNil(t, inst)
	})

	t.Run("with ignore stdio", func(t *testing.T) {
		opts := Options{
			IgnoreStdIO: true,
		}

		inst, err := CreateInstance("386", image, &opts)
		require.NoError(t, err)
		require.NotNil(t, inst)
	})

	t.Run("with not auto run", func(t *testing.T) {
		opts := Options{
			NotAutoRun: true,
		}

		inst, err := CreateInstance("386", image, &opts)
		require.NoError(t, err)
		require.NotNil(t, inst)
	})

	t.Run("with not stop runtime", func(t *testing.T) {
		opts := Options{
			NotStopRuntime: true,
		}

		inst, err := CreateInstance("386", image, &opts)
		require.NoError(t, err)
		require.NotNil(t, inst)
	})

	t.Run("with additional arguments", func(t *testing.T) {
		t.Run("common", func(t *testing.T) {
			args := []*argument.Arg{
				{ID: 100, Data: []byte("config data")},
			}
			opts := Options{
				Arguments: args,
			}

			inst, err := CreateInstance("386", image, &opts)
			require.NoError(t, err)
			require.NotNil(t, inst)
		})

		t.Run("invalid id", func(t *testing.T) {
			args := []*argument.Arg{
				{ID: 1, Data: []byte("config data")},
			}
			opts := Options{
				Arguments: args,
			}

			inst, err := CreateInstance("386", image, &opts)
			errStr := "additional argument id must greater than 64"
			require.EqualError(t, err, errStr)
			require.Nil(t, inst)
		})
	})

	t.Run("invalid image config", func(t *testing.T) {
		embed := NewEmbed([]byte{0x00})

		inst, err := CreateInstance("386", embed, nil)
		errStr := "invalid embed mode config: invalid PE image: EOF"
		require.EqualError(t, err, errStr)
		require.Nil(t, inst)
	})

	t.Run("invalid architecture", func(t *testing.T) {
		inst, err := CreateInstance("123", image, nil)
		require.EqualError(t, err, "invalid architecture: 123")
		require.Nil(t, inst)
	})

	t.Run("invalid template", func(t *testing.T) {
		opts := Options{
			Template: []byte{0x00},
		}

		inst, err := CreateInstance("386", image, &opts)
		require.EqualError(t, err, "invalid runtime template")
		require.Nil(t, inst)
	})

	t.Run("same argument id", func(t *testing.T) {
		args := []*argument.Arg{
			{ID: 100, Data: []byte("config data 1")},
			{ID: 100, Data: []byte("config data 2")},
		}
		opts := Options{
			Arguments: args,
		}

		inst, err := CreateInstance("386", image, &opts)
		errStr := "failed to encode argument: argument id 100 already exists"
		require.EqualError(t, err, errStr)
		require.Nil(t, inst)
	})
}
