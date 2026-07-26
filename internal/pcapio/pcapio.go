// Package pcapio reads and writes packet capture files (classic pcap and
// pcapng), auto-detecting the format on read. It is a thin wrapper around
// gopacket/pcapgo that decouples the rest of sekisho's tooling from the
// underlying capture format.
package pcapio

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// pcapng section header block type, used to distinguish pcapng files from
// classic pcap files by peeking at the first four bytes of the stream.
const ngBlockTypeSectionHeader = 0x0a0d0d0a

// Packet is one packet read from a capture, decoded far enough to access
// its protocol layers.
type Packet struct {
	// Timestamp is the capture timestamp recorded in the file.
	Timestamp time.Time
	// Raw is the full captured frame, including any link-layer header.
	// It is safe to retain: callers own this slice.
	Raw []byte
	// Decoded is the gopacket decoding of Raw, using the capture's link
	// type to select the first layer decoder.
	Decoded gopacket.Packet
}

// Reader reads packets from a pcap or pcapng stream.
type Reader struct {
	classic  *pcapgo.Reader
	ng       *pcapgo.NgReader
	linkType layers.LinkType
}

// NewReader wraps r, detecting whether it holds a classic pcap or a pcapng
// capture from its magic bytes. Only single-interface pcapng captures are
// supported: the link type of the first interface description block is
// used for every packet.
func NewReader(r io.Reader) (*Reader, error) {
	br := bufio.NewReader(r)
	magic, err := br.Peek(4)
	if err != nil {
		return nil, fmt.Errorf("pcapio: read magic bytes: %w", err)
	}

	// pcapng always starts with a Section Header Block whose type field is
	// 0x0A0D0D0A, written in the file's own byte order — so it reads the
	// same in both orderings and a single big-endian check suffices.
	if binary.BigEndian.Uint32(magic) == ngBlockTypeSectionHeader {
		ngr, err := pcapgo.NewNgReader(br, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return nil, fmt.Errorf("pcapio: open pcapng reader: %w", err)
		}
		return &Reader{ng: ngr, linkType: ngr.LinkType()}, nil
	}

	pr, err := pcapgo.NewReader(br)
	if err != nil {
		return nil, fmt.Errorf("pcapio: open pcap reader: %w", err)
	}
	return &Reader{classic: pr, linkType: pr.LinkType()}, nil
}

// LinkType returns the capture's link-layer type.
func (r *Reader) LinkType() layers.LinkType {
	return r.linkType
}

// Next returns the next packet in the capture, or io.EOF once the capture
// is exhausted.
func (r *Reader) Next() (*Packet, error) {
	var data []byte
	var ci gopacket.CaptureInfo
	var err error
	if r.ng != nil {
		data, ci, err = r.ng.ZeroCopyReadPacketData()
	} else {
		data, ci, err = r.classic.ZeroCopyReadPacketData()
	}
	if err != nil {
		return nil, err
	}

	// ZeroCopyReadPacketData reuses its internal buffer on the next call,
	// so callers that retain the packet must copy it first.
	raw := make([]byte, len(data))
	copy(raw, data)

	// r.linkType itself implements gopacket.Decoder (it dispatches through
	// layers.LinkTypeMetadata), which is the supported way to decode the
	// first layer from a link type — layers.LinkType.LayerType() is not
	// reliably populated for all link types and must not be used here.
	decoded := gopacket.NewPacket(raw, r.linkType, gopacket.Default)
	return &Packet{Timestamp: ci.Timestamp, Raw: raw, Decoded: decoded}, nil
}

// Writer writes packets to a classic pcap stream.
type Writer struct {
	w *pcapgo.Writer
}

// NewWriter creates a classic pcap writer, writing the file header
// immediately.
func NewWriter(w io.Writer, linkType layers.LinkType, snaplen uint32) (*Writer, error) {
	pw := pcapgo.NewWriter(w)
	if err := pw.WriteFileHeader(snaplen, linkType); err != nil {
		return nil, fmt.Errorf("pcapio: write file header: %w", err)
	}
	return &Writer{w: pw}, nil
}

// WritePacket appends one packet with the given capture timestamp.
func (w *Writer) WritePacket(ts time.Time, data []byte) error {
	ci := gopacket.CaptureInfo{
		Timestamp:     ts,
		CaptureLength: len(data),
		Length:        len(data),
	}
	return w.w.WritePacket(ci, data)
}
