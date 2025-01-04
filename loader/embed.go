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
	disableCompress = 0
	enableCompress  = 1
)

// Embed is the embed mode.
type Embed struct {
	image []byte

	compress   bool
	windowSize int

	preCompress bool
	rawSize     int
}

// NewEmbed is used to create image config with embed mode.
func NewEmbed(image []byte) Image {
	return &Embed{image: image}
}

// NewEmbedCompress is used to create embed with compression.
func NewEmbedCompress(image []byte, windowSize int) Image {
	return &Embed{
		image:      image,
		compress:   true,
		windowSize: windowSize,
	}
}

// NewEmbedPreCompress is used to create embed with pre-compression.
func NewEmbedPreCompress(image []byte, rawSize int) Image {
	return &Embed{
		image:       image,
		compress:    true,
		preCompress: true,
		rawSize:     rawSize,
	}
}

// Encode implement Image interface.
func (e *Embed) Encode() ([]byte, error) {
	// check PE image is valid
	image := e.image
	if e.preCompress {
		image = lzss.Decompress(image, e.rawSize)
	}
	_, err := pe.NewFile(bytes.NewReader(image))
	if err != nil {
		return nil, fmt.Errorf("invalid PE image: %s", err)
	}
	config := bytes.NewBuffer(make([]byte, 0, 16))
	// write the mode
	config.WriteByte(modeEmbed)
	// need use compress mode
	if !e.compress {
		size := binary.LittleEndian.AppendUint32(nil, uint32(len(e.image)))
		config.WriteByte(disableCompress)
		config.Write(size)
		config.Write(e.image)
		return config.Bytes(), nil
	}
	// set the compressed flag
	config.WriteByte(enableCompress)
	// compress PE image
	var (
		compressed []byte
		rawSize    int
	)
	if !e.preCompress {
		compressed, err = lzss.Compress(e.image, e.windowSize)
		if err != nil {
			return nil, fmt.Errorf("failed to compress PE image: %s", err)
		}
		rawSize = len(e.image)
	} else {
		compressed = e.image
		rawSize = e.rawSize
	}
	// write raw size
	config.Write(binary.LittleEndian.AppendUint32(nil, uint32(rawSize)))
	// write compressed size
	config.Write(binary.LittleEndian.AppendUint32(nil, uint32(len(compressed))))
	// write compressed PE image
	config.Write(compressed)
	return config.Bytes(), nil
}

// Mode implement Image interface.
func (e *Embed) Mode() string {
	return ModeEmbed
}
