package loader

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"

	"github.com/For-ACGN/LZSS"
)

// enable compression
// +-----------+----------+----------+-----------------+-------+
// | mode flag | compress | raw size | compressed size | image |
// +-----------+----------+----------+-----------------+-------+
// |   byte    |   bool   |  uint32  |     uint32      |  var  |
// +-----------+----------+----------+-----------------+-------+

// disable compression
// +-----------+----------+--------+-------+
// | mode flag | compress |  size  | image |
// +-----------+----------+--------+-------+
// |   byte    |   bool   | uint32 |  var  |
// +-----------+----------+--------+-------+

const modeEmbed = 1

const (
	enableCompression  = 1
	disableCompression = 0
)

// Embed is the embed mode.
type Embed struct {
	image []byte
	opts  EmbedOptions
}

// EmbedOptions contains Embed mode options.
type EmbedOptions struct {
	Compress      bool `toml:"compress"       json:"compress"`
	WindowSize    int  `toml:"window_size"    json:"window_size"`
	ChainLen      int  `toml:"chain_len"      json:"chain_len"`
	PreCompressed bool `toml:"pre_compressed" json:"pre_compressed"`
}

// NewEmbed is used to create image with embed mode.
func NewEmbed(image []byte, opts *EmbedOptions) Image {
	if opts == nil {
		opts = new(EmbedOptions)
	}
	return &Embed{image: image, opts: *opts}
}

// Encode implement Image interface.
func (e *Embed) Encode() ([]byte, error) {
	// check PE image is valid
	image := e.image
	if e.opts.PreCompressed {
		var err error
		image, err = lzss.Decompress(image)
		if err != nil {
			return nil, fmt.Errorf("invalid precompressed PE image: %s", err)
		}
	}
	_, err := pe.NewFile(bytes.NewReader(image))
	if err != nil {
		return nil, fmt.Errorf("invalid PE image: %s", err)
	}
	buffer := bytes.NewBuffer(make([]byte, 0, 16*1024))
	// write the mode
	buffer.WriteByte(modeEmbed)
	// disable compression
	if !e.opts.Compress && !e.opts.PreCompressed {
		size := binary.LittleEndian.AppendUint32(nil, uint32(len(e.image))) // #nosec
		buffer.WriteByte(disableCompression)
		buffer.Write(size)
		buffer.Write(e.image)
		return buffer.Bytes(), nil
	}
	// set the compressed flag
	buffer.WriteByte(enableCompression)
	// compress PE image
	var compressed []byte
	if e.opts.PreCompressed {
		compressed = e.image
	} else {
		compressed, err = lzss.Compress(e.image, e.opts.WindowSize, e.opts.ChainLen)
		if err != nil {
			return nil, fmt.Errorf("failed to compress PE image: %s", err)
		}
	}
	// write raw size
	size := binary.LittleEndian.AppendUint32(nil, uint32(len(image))) // #nosec
	buffer.Write(size)
	// write compressed size
	size = binary.LittleEndian.AppendUint32(nil, uint32(len(compressed))) // #nosec
	buffer.Write(size)
	// write compressed PE image
	buffer.Write(compressed)
	return buffer.Bytes(), nil
}

// Mode implement Image interface.
func (e *Embed) Mode() string {
	return ModeEmbed
}
