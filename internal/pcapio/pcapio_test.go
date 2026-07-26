package pcapio

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// buildUDPFrame serializes a minimal Ethernet/IPv4/UDP frame carrying
// payload, for use as test fixture data.
func buildUDPFrame(t *testing.T, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    srcIP, DstIP: dstIP,
	}
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	return buf.Bytes()
}

func TestReaderWriterRoundTrip_ClassicPcap(t *testing.T) {
	frame1 := buildUDPFrame(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 40000, 162, []byte("trap-payload-1"))
	frame2 := buildUDPFrame(t, net.IPv4(10, 0, 0, 3), net.IPv4(10, 0, 0, 4), 40001, 161, []byte("not-a-trap"))

	var buf bytes.Buffer
	w, err := NewWriter(&buf, layers.LinkTypeEthernet, 65535)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	ts1 := time.Date(2026, 7, 26, 10, 0, 0, 0, time.UTC)
	ts2 := ts1.Add(500 * time.Millisecond)
	if err := w.WritePacket(ts1, frame1); err != nil {
		t.Fatalf("WritePacket 1: %v", err)
	}
	if err := w.WritePacket(ts2, frame2); err != nil {
		t.Fatalf("WritePacket 2: %v", err)
	}

	r, err := NewReader(&buf)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	if r.LinkType() != layers.LinkTypeEthernet {
		t.Fatalf("LinkType() = %v, want Ethernet", r.LinkType())
	}

	pkt1, err := r.Next()
	if err != nil {
		t.Fatalf("Next() 1: %v", err)
	}
	if !pkt1.Timestamp.Equal(ts1) {
		t.Errorf("packet 1 timestamp = %v, want %v", pkt1.Timestamp, ts1)
	}
	if !bytes.Equal(pkt1.Raw, frame1) {
		t.Errorf("packet 1 raw bytes mismatch")
	}
	udpLayer := pkt1.Decoded.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		t.Fatalf("packet 1: no UDP layer decoded")
	}
	udp := udpLayer.(*layers.UDP)
	if udp.DstPort != 162 {
		t.Errorf("packet 1 dst port = %v, want 162", udp.DstPort)
	}
	if !bytes.Equal(udp.Payload, []byte("trap-payload-1")) {
		t.Errorf("packet 1 payload = %q, want %q", udp.Payload, "trap-payload-1")
	}

	pkt2, err := r.Next()
	if err != nil {
		t.Fatalf("Next() 2: %v", err)
	}
	if !bytes.Equal(pkt2.Raw, frame2) {
		t.Errorf("packet 2 raw bytes mismatch")
	}

	if _, err := r.Next(); err != io.EOF {
		t.Fatalf("Next() at end = %v, want io.EOF", err)
	}
}

func TestReader_DetectsPcapng(t *testing.T) {
	frame := buildUDPFrame(t, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 40000, 162, []byte("ng-payload"))

	var buf bytes.Buffer
	w, err := pcapgo.NewNgWriter(&buf, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("NewNgWriter: %v", err)
	}
	ts := time.Date(2026, 7, 26, 11, 0, 0, 0, time.UTC)
	if err := w.WritePacket(gopacket.CaptureInfo{
		Timestamp: ts, CaptureLength: len(frame), Length: len(frame),
	}, frame); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	r, err := NewReader(&buf)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	if r.LinkType() != layers.LinkTypeEthernet {
		t.Fatalf("LinkType() = %v, want Ethernet", r.LinkType())
	}
	pkt, err := r.Next()
	if err != nil {
		t.Fatalf("Next(): %v", err)
	}
	if !bytes.Equal(pkt.Raw, frame) {
		t.Errorf("raw bytes mismatch for pcapng-sourced packet")
	}
	udpLayer := pkt.Decoded.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		t.Fatalf("no UDP layer decoded from pcapng-sourced packet (err layer: %v)", pkt.Decoded.ErrorLayer())
	}
	if got := udpLayer.(*layers.UDP).Payload; !bytes.Equal(got, []byte("ng-payload")) {
		t.Errorf("payload = %q, want %q", got, "ng-payload")
	}
}

func TestReader_EmptyCapture(t *testing.T) {
	var buf bytes.Buffer
	if _, err := NewWriter(&buf, layers.LinkTypeEthernet, 65535); err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	r, err := NewReader(&buf)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	if _, err := r.Next(); err != io.EOF {
		t.Fatalf("Next() on empty capture = %v, want io.EOF", err)
	}
}
