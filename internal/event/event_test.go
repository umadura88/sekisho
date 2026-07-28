package event

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/umadura88/sekisho/internal/snmpcodec"
)

func oid(s string) snmpcodec.ObjectIdentifier {
	o, err := snmpcodec.ParseOID(s)
	if err != nil {
		panic(err)
	}
	return o
}

var fixedTime = time.Date(2026, 7, 28, 9, 0, 0, 0, time.UTC)

// TestBuild_V2LinkDown_GoldenJSON pins the golden JSON shape for the
// HLD §1.1.1 linkDown example (M1a DoD ①: this exact serialization is what
// fixture-replay runs are compared against).
func TestBuild_V2LinkDown_GoldenJSON(t *testing.T) {
	msg := &snmpcodec.Message{
		Version: snmpcodec.VersionV2c, Community: "public",
		PDUType: snmpcodec.PDUTrapV2, RequestID: 1,
		Varbinds: []snmpcodec.Varbind{
			{Name: oid("1.3.6.1.2.1.1.3.0"), Value: snmpcodec.Value{Type: snmpcodec.TypeTimeTicks, UInt: 512345600}},
			{Name: oid("1.3.6.1.6.3.1.1.4.1.0"), Value: snmpcodec.Value{Type: snmpcodec.TypeObjectIdentifier, OID: oid("1.3.6.1.6.3.1.1.5.3")}},
			{Name: oid("1.3.6.1.2.1.2.2.1.1.1000"), Value: snmpcodec.Value{Type: snmpcodec.TypeInteger, Int: 1000}},
			{Name: oid("1.3.6.1.2.1.2.2.1.7.1000"), Value: snmpcodec.Value{Type: snmpcodec.TypeInteger, Int: 1}},
			{Name: oid("1.3.6.1.2.1.2.2.1.8.1000"), Value: snmpcodec.Value{Type: snmpcodec.TypeInteger, Int: 2}},
		},
	}
	ev, err := Build("evt-0001", fixedTime, "10.0.0.1:40000", msg, []byte{0x30, 0x00})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	got, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"event_id":"evt-0001","received_at":"2026-07-28T09:00:00Z","source_addr":"10.0.0.1:40000","device_id":"10.0.0.1","version":"v2c","trap_oid":"1.3.6.1.6.3.1.1.5.3","sys_uptime":512345600,"varbinds":[{"oid":"1.3.6.1.2.1.1.3.0","type":"TimeTicks","value":"512345600"},{"oid":"1.3.6.1.6.3.1.1.4.1.0","type":"OID","value":"1.3.6.1.6.3.1.1.5.3"},{"oid":"1.3.6.1.2.1.2.2.1.1.1000","type":"Integer","value":"1000"},{"oid":"1.3.6.1.2.1.2.2.1.7.1000","type":"Integer","value":"1"},{"oid":"1.3.6.1.2.1.2.2.1.8.1000","type":"Integer","value":"2"}],"raw_pdu":"MAA="}`
	if string(got) != want {
		t.Errorf("golden JSON mismatch:\n got:  %s\n want: %s", got, want)
	}
}

// TestBuild_V1Normalization covers M1a DoD ②: a v1 trap is normalized into
// the same event shape as v2 — sysUpTime.0 and the derived snmpTrapOID.0
// prepended, agent-addr appended as snmpTrapAddress.0, and device_id
// resolved from the agent-addr (not the packet source).
func TestBuild_V1Normalization(t *testing.T) {
	msg := &snmpcodec.Message{
		Version: snmpcodec.VersionV1, Community: "public",
		PDUType:      snmpcodec.PDUTrapV1,
		Enterprise:   oid("1.3.6.1.4.1.9999"),
		AgentAddr:    net.IPv4(10, 0, 0, 33).To4(),
		GenericTrap:  6,
		SpecificTrap: 42,
		Timestamp:    777,
		Varbinds: []snmpcodec.Varbind{
			{Name: oid("1.3.6.1.4.1.9999.1.1"), Value: snmpcodec.Value{Type: snmpcodec.TypeOctetString, Str: []byte("payload")}},
		},
	}
	// Packet source is a forwarder, NOT the device (the forward scenario
	// of HLD §10.1).
	ev, err := Build("evt-0002", fixedTime, "192.0.2.100:1620", msg, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if ev.Version != "v1" {
		t.Errorf("Version = %q, want v1", ev.Version)
	}
	if ev.TrapOID != "1.3.6.1.4.1.9999.0.42" {
		t.Errorf("TrapOID = %q, want RFC 3584 derivation 1.3.6.1.4.1.9999.0.42", ev.TrapOID)
	}
	if ev.DeviceID != "10.0.0.33" {
		t.Errorf("DeviceID = %q, want agent-addr 10.0.0.33", ev.DeviceID)
	}
	if ev.SysUptime != 777 {
		t.Errorf("SysUptime = %d, want 777", ev.SysUptime)
	}

	wantOIDs := []string{
		"1.3.6.1.2.1.1.3.0",     // prepended sysUpTime.0
		"1.3.6.1.6.3.1.1.4.1.0", // prepended snmpTrapOID.0
		"1.3.6.1.4.1.9999.1.1",  // original varbind
		"1.3.6.1.6.3.18.1.3.0",  // appended snmpTrapAddress.0
	}
	if len(ev.Varbinds) != len(wantOIDs) {
		t.Fatalf("varbind count = %d, want %d (%+v)", len(ev.Varbinds), len(wantOIDs), ev.Varbinds)
	}
	for i, w := range wantOIDs {
		if ev.Varbinds[i].OID != w {
			t.Errorf("Varbinds[%d].OID = %q, want %q", i, ev.Varbinds[i].OID, w)
		}
	}
	if ev.Varbinds[3].Value != "10.0.0.33" {
		t.Errorf("snmpTrapAddress value = %q, want 10.0.0.33", ev.Varbinds[3].Value)
	}
}

// TestBuild_V2ForwardedDeviceID: a v2c trap that itself carries
// snmpTrapAddress.0 (e.g. one that passed through a v1->v2 conversion
// upstream) resolves device_id from the varbind, not the packet source.
func TestBuild_V2ForwardedDeviceID(t *testing.T) {
	msg := &snmpcodec.Message{
		Version: snmpcodec.VersionV2c, Community: "public",
		PDUType: snmpcodec.PDUTrapV2, RequestID: 3,
		Varbinds: []snmpcodec.Varbind{
			{Name: oid("1.3.6.1.2.1.1.3.0"), Value: snmpcodec.Value{Type: snmpcodec.TypeTimeTicks, UInt: 1}},
			{Name: oid("1.3.6.1.6.3.1.1.4.1.0"), Value: snmpcodec.Value{Type: snmpcodec.TypeObjectIdentifier, OID: oid("1.3.6.1.6.3.1.1.5.4")}},
			{Name: oid("1.3.6.1.6.3.18.1.3.0"), Value: snmpcodec.Value{Type: snmpcodec.TypeIPAddress, IP: net.IPv4(10, 9, 9, 9).To4()}},
		},
	}
	ev, err := Build("evt-0003", fixedTime, "192.0.2.100:1620", msg, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if ev.DeviceID != "10.9.9.9" {
		t.Errorf("DeviceID = %q, want 10.9.9.9 (from snmpTrapAddress.0)", ev.DeviceID)
	}
}

func TestBuild_RejectsNonTrap(t *testing.T) {
	msg := &snmpcodec.Message{
		Version: snmpcodec.VersionV2c, Community: "public",
		PDUType: snmpcodec.PDUGetRequest, RequestID: 9,
	}
	if _, err := Build("x", fixedTime, "10.0.0.1:1", msg, nil); err == nil {
		t.Fatal("Build(GetRequest): want error, got nil")
	}
}

func TestBuild_RejectsV2TrapWithoutTrapOID(t *testing.T) {
	msg := &snmpcodec.Message{
		Version: snmpcodec.VersionV2c, Community: "public",
		PDUType: snmpcodec.PDUTrapV2, RequestID: 9,
		Varbinds: []snmpcodec.Varbind{
			{Name: oid("1.3.6.1.2.1.1.3.0"), Value: snmpcodec.Value{Type: snmpcodec.TypeTimeTicks, UInt: 1}},
		},
	}
	_, err := Build("x", fixedTime, "10.0.0.1:1", msg, nil)
	if err == nil || !strings.Contains(err.Error(), "snmpTrapOID") {
		t.Fatalf("Build without snmpTrapOID: err = %v, want snmpTrapOID error", err)
	}
}
