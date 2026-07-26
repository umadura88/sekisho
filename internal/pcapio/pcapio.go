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
	"net"
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

// NewEthernetWriter creates a classic pcap writer with an Ethernet link
// type and the conventional 64KB snap length — the framing used for
// synthetic fixture files.
func NewEthernetWriter(w io.Writer) (*Writer, error) {
	return NewWriter(w, layers.LinkTypeEthernet, 65535)
}

// Synthetic MAC addresses used by BuildUDPFrame. The link-layer framing of
// generated fixtures carries no information; it exists only so the payload
// can live in a valid pcap and be replayed.
var (
	syntheticSrcMAC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	syntheticDstMAC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
)

// BuildUDPFrame serializes an Ethernet/IPv4/UDP frame carrying payload,
// with header lengths and checksums computed. Used to wrap synthetic SNMP
// messages into pcap fixtures.
func BuildUDPFrame(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) ([]byte, error) {
	eth := &layers.Ethernet{
		SrcMAC: syntheticSrcMAC, DstMAC: syntheticDstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    srcIP, DstIP: dstIP,
	}
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, err
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
