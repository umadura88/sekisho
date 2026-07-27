package inspect

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/umadura88/sekisho/internal/pcapio"
	"github.com/umadura88/sekisho/internal/snmpcodec"
)

func oid(s string) snmpcodec.ObjectIdentifier {
	o, err := snmpcodec.ParseOID(s)
	if err != nil {
		panic(err)
	}
	return o
}

// buildCapture assembles a small in-memory pcap:
//   - 2 × v2c linkDown traps (same kind)
//   - 1 × v1 enterprise-specific trap
//   - 1 × UDP packet to a non-trap port (must be ignored)
//   - 1 × UDP/162 packet with a garbage payload (decode failure)
func buildCapture(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := pcapio.NewEthernetWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Date(2026, 7, 27, 9, 0, 0, 0, time.UTC)

	write := func(srcIP net.IP, dstPort uint16, payload []byte) {
		frame, err := pcapio.BuildUDPFrame(srcIP, net.IPv4(10, 0, 0, 200), 40000, dstPort, payload)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.WritePacket(ts, frame); err != nil {
			t.Fatal(err)
		}
		ts = ts.Add(time.Second)
	}

	linkDown := &snmpcodec.Message{
		Version: snmpcodec.VersionV2c, Community: "public",
		PDUType: snmpcodec.PDUTrapV2, RequestID: 1,
		Varbinds: []snmpcodec.Varbind{
			{Name: oid("1.3.6.1.2.1.1.3.0"), Value: snmpcodec.Value{Type: snmpcodec.TypeTimeTicks, UInt: 100}},
			{Name: oid("1.3.6.1.6.3.1.1.4.1.0"), Value: snmpcodec.Value{Type: snmpcodec.TypeObjectIdentifier, OID: oid("1.3.6.1.6.3.1.1.5.3")}},
			{Name: oid("1.3.6.1.2.1.2.2.1.1.1000"), Value: snmpcodec.Value{Type: snmpcodec.TypeInteger, Int: 1000}},
		},
	}
	ldPayload, err := linkDown.Encode()
	if err != nil {
		t.Fatal(err)
	}
	write(net.IPv4(10, 0, 0, 1), 162, ldPayload)
	write(net.IPv4(10, 0, 0, 2), 162, ldPayload)

	v1 := &snmpcodec.Message{
		Version: snmpcodec.VersionV1, Community: "public",
		PDUType:      snmpcodec.PDUTrapV1,
		Enterprise:   oid("1.3.6.1.4.1.9999"),
		AgentAddr:    net.IPv4(10, 0, 0, 3).To4(),
		GenericTrap:  6,
		SpecificTrap: 42,
		Timestamp:    5,
	}
	v1Payload, err := v1.Encode()
	if err != nil {
		t.Fatal(err)
	}
	write(net.IPv4(10, 0, 0, 99), 162, v1Payload) // packet src differs from agent-addr

	write(net.IPv4(10, 0, 0, 4), 5000, []byte("not a trap port"))
	write(net.IPv4(10, 0, 0, 5), 162, []byte("garbage, not BER"))

	return buf.Bytes()
}

func TestRun_StatsAndFrequency(t *testing.T) {
	capture := buildCapture(t)
	var out bytes.Buffer
	stats, err := Run(bytes.NewReader(capture), &out, Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if stats.Total != 5 || stats.Matched != 4 || stats.Decoded != 3 || stats.Failures != 1 {
		t.Errorf("stats = %+v, want Total=5 Matched=4 Decoded=3 Failures=1", stats)
	}
	if stats.V1 != 1 || stats.V2c != 2 {
		t.Errorf("version mix = v1:%d v2c:%d, want 1/2", stats.V1, stats.V2c)
	}
	if got := stats.Freq["1.3.6.1.6.3.1.1.5.3"]; got != 2 {
		t.Errorf("linkDown freq = %d, want 2", got)
	}
	// RFC 3584 derivation for the v1 enterprise-specific trap.
	if got := stats.Freq["1.3.6.1.4.1.9999.0.42"]; got != 1 {
		t.Errorf("v1-derived trap freq = %d, want 1 (keys: %v)", got, stats.Freq)
	}
	if len(stats.ErrSample) != 1 {
		t.Errorf("ErrSample = %v, want exactly 1 entry", stats.ErrSample)
	}

	text := out.String()
	if !strings.Contains(text, "trap=1.3.6.1.6.3.1.1.5.3") {
		t.Error("per-trap line for linkDown missing")
	}
	// The v1 trap's source must be the agent-addr, not the packet source.
	if !strings.Contains(text, "10.0.0.3") {
		t.Error("v1 agent-addr not used as source")
	}
	if !strings.Contains(text, "matched(udp/162)=4 decoded=3 failures=1") {
		t.Errorf("summary line missing or wrong:\n%s", text)
	}
}

func TestRun_JSONMode(t *testing.T) {
	capture := buildCapture(t)
	var out bytes.Buffer
	if _, err := Run(bytes.NewReader(capture), &out, Options{JSON: true, Limit: 1}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, `"trap_oid":"1.3.6.1.6.3.1.1.5.3"`) {
		t.Errorf("JSON output missing trap_oid:\n%s", text)
	}
	if !strings.Contains(text, `"oid":"1.3.6.1.2.1.2.2.1.1.1000"`) {
		t.Errorf("JSON output missing decomposed varbind:\n%s", text)
	}
	// Limit=1: exactly one JSON line before the summary.
	if got := strings.Count(text, `"trap_oid"`); got != 1 {
		t.Errorf("printed %d JSON lines, want 1 (Limit)", got)
	}
}

func TestRun_StatsOnly(t *testing.T) {
	capture := buildCapture(t)
	var out bytes.Buffer
	stats, err := Run(bytes.NewReader(capture), &out, Options{StatsOnly: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if stats.Decoded != 3 {
		t.Errorf("Decoded = %d, want 3", stats.Decoded)
	}
	if strings.Contains(out.String(), "trap=") {
		t.Error("StatsOnly must suppress per-trap lines")
	}
}
