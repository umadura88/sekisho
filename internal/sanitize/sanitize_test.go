package sanitize

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/umadura88/sekisho/internal/pcapio"
	"github.com/umadura88/sekisho/internal/snmpcodec"
)

// secretPacket returns bytes for one synthetic "real" capture packet
// carrying values that must never survive sanitization.
const (
	secretSrcIP     = "192.168.55.10"
	secretDstIP     = "192.168.55.1"
	secretVarbindIP = "192.168.55.99"
	secretCommunity = "SECRET-COMMUNITY"
	secretString    = "topsecret-device-name"
)

func oid(s string) snmpcodec.ObjectIdentifier {
	o, err := snmpcodec.ParseOID(s)
	if err != nil {
		panic(err)
	}
	return o
}

func buildSecretCapture(t *testing.T) []byte {
	t.Helper()
	msg := &snmpcodec.Message{
		Version:   snmpcodec.VersionV2c,
		Community: secretCommunity,
		PDUType:   snmpcodec.PDUTrapV2,
		RequestID: 1,
		Varbinds: []snmpcodec.Varbind{
			{Name: oid("1.3.6.1.2.1.1.3.0"), Value: snmpcodec.Value{Type: snmpcodec.TypeTimeTicks, UInt: 100}},
			{Name: oid("1.3.6.1.6.3.1.1.4.1.0"), Value: snmpcodec.Value{Type: snmpcodec.TypeObjectIdentifier, OID: oid("1.3.6.1.6.3.1.1.5.3")}},
			{Name: oid("1.3.6.1.4.1.9999.1.1"), Value: snmpcodec.Value{Type: snmpcodec.TypeIPAddress, IP: net.ParseIP(secretVarbindIP).To4()}},
			{Name: oid("1.3.6.1.4.1.9999.1.2"), Value: snmpcodec.Value{Type: snmpcodec.TypeOctetString, Str: []byte(secretString)}},
		},
	}
	payload, err := msg.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	frame, err := buildFrame(net.ParseIP(secretSrcIP), net.ParseIP(secretDstIP), 40000, 162, payload)
	if err != nil {
		t.Fatalf("buildFrame: %v", err)
	}

	var buf bytes.Buffer
	w, err := pcapio.NewWriter(&buf, layers.LinkTypeEthernet, 65535)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.WritePacket(time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC), frame); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	return buf.Bytes()
}

// TestSanitize_NoSecretBytesSurvive covers M0b DoD item ①: none of the
// original IPs, community, or scrubbed string appear anywhere in the
// output bytes.
func TestSanitize_NoSecretBytesSurvive(t *testing.T) {
	capture := buildSecretCapture(t)

	var out, warn bytes.Buffer
	mapper := NewIPMapper("test-seed")
	stats, err := Sanitize(bytes.NewReader(capture), &out, &warn, mapper, Options{ScrubStrings: true})
	if err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	if stats.Total != 1 || stats.Sanitized != 1 || stats.Skipped != 0 {
		t.Fatalf("stats = %+v, want Total=1 Sanitized=1 Skipped=0", stats)
	}

	secrets := []string{secretSrcIP, secretDstIP, secretVarbindIP, secretCommunity, secretString}
	for _, s := range secrets {
		if bytes.Contains(out.Bytes(), []byte(s)) {
			t.Errorf("sanitized output still contains secret %q", s)
		}
	}
}

// TestSanitize_DeterministicAcrossRuns covers M0b DoD item ②: the same
// seed produces byte-identical output on independent runs.
func TestSanitize_DeterministicAcrossRuns(t *testing.T) {
	capture := buildSecretCapture(t)

	run := func() []byte {
		var out, warn bytes.Buffer
		mapper := NewIPMapper("consistent-seed")
		if _, err := Sanitize(bytes.NewReader(capture), &out, &warn, mapper, Options{ScrubStrings: true}); err != nil {
			t.Fatalf("Sanitize: %v", err)
		}
		return out.Bytes()
	}

	out1 := run()
	out2 := run()
	if !bytes.Equal(out1, out2) {
		t.Error("two runs with the same seed produced different output")
	}

	var out3 bytes.Buffer
	var warn bytes.Buffer
	mapper := NewIPMapper("different-seed")
	if _, err := Sanitize(bytes.NewReader(capture), &out3, &warn, mapper, Options{ScrubStrings: true}); err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	if bytes.Equal(out1, out3.Bytes()) {
		t.Error("a different seed produced identical output — seed is not affecting the mapping")
	}
}

// TestSanitize_OutputIsReplayableAndDecodable covers M0b DoD item ③:
// the sanitized pcap can be read back with pcapio and its payload
// re-decoded with snmpcodec, with the expected anonymized values.
func TestSanitize_OutputIsReplayableAndDecodable(t *testing.T) {
	capture := buildSecretCapture(t)

	var out, warn bytes.Buffer
	mapper := NewIPMapper("test-seed")
	if _, err := Sanitize(bytes.NewReader(capture), &out, &warn, mapper, Options{ScrubStrings: true, Community: "public"}); err != nil {
		t.Fatalf("Sanitize: %v", err)
	}

	rdr, err := pcapio.NewReader(bytes.NewReader(out.Bytes()))
	if err != nil {
		t.Fatalf("pcapio.NewReader on sanitized output: %v", err)
	}
	pkt, err := rdr.Next()
	if err != nil {
		t.Fatalf("read sanitized packet: %v", err)
	}
	if _, err := rdr.Next(); err != io.EOF {
		t.Fatalf("expected exactly one packet in sanitized output, got another")
	}

	udpLayer := pkt.Decoded.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		t.Fatalf("sanitized packet has no UDP layer (layers: %v)", pkt.Decoded.Layers())
	}
	udp := udpLayer.(*layers.UDP)

	msg, err := snmpcodec.Decode(udp.Payload)
	if err != nil {
		t.Fatalf("snmpcodec.Decode(sanitized payload): %v", err)
	}
	if msg.Community != "public" {
		t.Errorf("Community = %q, want %q", msg.Community, "public")
	}

	wantVarbindIP := mapper.Map(net.ParseIP(secretVarbindIP).To4())
	if !msg.Varbinds[2].Value.IP.Equal(wantVarbindIP) {
		t.Errorf("varbind IP = %v, want %v", msg.Varbinds[2].Value.IP, wantVarbindIP)
	}
	if got := string(msg.Varbinds[3].Value.Str); got != "scrubbed-1" {
		t.Errorf("scrubbed string varbind = %q, want %q", got, "scrubbed-1")
	}

	ip4Layer := pkt.Decoded.Layer(layers.LayerTypeIPv4)
	ip4 := ip4Layer.(*layers.IPv4)
	wantSrc := mapper.Map(net.ParseIP(secretSrcIP))
	wantDst := mapper.Map(net.ParseIP(secretDstIP))
	if !ip4.SrcIP.Equal(wantSrc) {
		t.Errorf("IPv4 src = %v, want %v", ip4.SrcIP, wantSrc)
	}
	if !ip4.DstIP.Equal(wantDst) {
		t.Errorf("IPv4 dst = %v, want %v", ip4.DstIP, wantDst)
	}
}

// TestSanitize_SkipsUndecodablePackets ensures packets that cannot be
// safely sanitized are dropped, not passed through with secrets intact.
func TestSanitize_SkipsUndecodablePackets(t *testing.T) {
	eth := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{0, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: net.ParseIP(secretSrcIP), DstIP: net.ParseIP(secretDstIP)}
	udp := &layers.UDP{SrcPort: 40000, DstPort: 162}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	// Garbage payload: not a valid BER SNMP message.
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
		eth, ip, udp, gopacket.Payload([]byte("not snmp"))); err != nil {
		t.Fatal(err)
	}

	var capBuf bytes.Buffer
	w, err := pcapio.NewWriter(&capBuf, layers.LinkTypeEthernet, 65535)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WritePacket(time.Now(), buf.Bytes()); err != nil {
		t.Fatal(err)
	}

	var out, warn bytes.Buffer
	mapper := NewIPMapper("seed")
	stats, err := Sanitize(bytes.NewReader(capBuf.Bytes()), &out, &warn, mapper, Options{})
	if err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	if stats.Total != 1 || stats.Sanitized != 0 || stats.Skipped != 1 {
		t.Fatalf("stats = %+v, want Total=1 Sanitized=0 Skipped=1", stats)
	}
	if bytes.Contains(out.Bytes(), []byte(secretSrcIP)) {
		t.Error("skipped packet's secret IP leaked into output")
	}
	if warn.Len() == 0 {
		t.Error("expected a warning to be written for the skipped packet")
	}
}
