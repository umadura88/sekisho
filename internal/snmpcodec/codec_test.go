package snmpcodec

import (
	"bytes"
	"net"
	"reflect"
	"testing"
)

func oid(s string) ObjectIdentifier {
	o, err := ParseOID(s)
	if err != nil {
		panic(err)
	}
	return o
}

// mustRoundTrip encodes m, decodes the result, and asserts the decoded
// message equals m. It also asserts that encoding the decoded message a
// second time produces byte-identical output to the first encoding — the
// "decode(encode(m)) == m, and re-encoding is idempotent" contract required
// by plan.html §4.2.
func mustRoundTrip(t *testing.T, m *Message) []byte {
	t.Helper()
	encoded1, err := m.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := Decode(encoded1)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !reflect.DeepEqual(m, decoded) {
		t.Fatalf("round trip mismatch:\n  original: %+v\n  decoded:  %+v", m, decoded)
	}
	encoded2, err := decoded.Encode()
	if err != nil {
		t.Fatalf("re-Encode: %v", err)
	}
	if !bytes.Equal(encoded1, encoded2) {
		t.Fatalf("re-encoding is not idempotent:\n  first:  % x\n  second: % x", encoded1, encoded2)
	}
	return encoded1
}

// TestLinkDownV2c mirrors the exact linkDown trap example from HLD §1.1.1
// (Figure 1): device 10.0.0.1, ifIndex 1000, ifOperStatus down(2).
func TestLinkDownV2c(t *testing.T) {
	m := &Message{
		Version:   VersionV2c,
		Community: "public",
		PDUType:   PDUTrapV2,
		RequestID: 12345,
		Varbinds: []Varbind{
			{Name: oid("1.3.6.1.2.1.1.3.0"), Value: Value{Type: TypeTimeTicks, UInt: 512345600}},
			{Name: oid("1.3.6.1.6.3.1.1.4.1.0"), Value: Value{Type: TypeObjectIdentifier, OID: oid("1.3.6.1.6.3.1.1.5.3")}},
			{Name: oid("1.3.6.1.2.1.2.2.1.1.1000"), Value: Value{Type: TypeInteger, Int: 1000}},
			{Name: oid("1.3.6.1.2.1.2.2.1.7.1000"), Value: Value{Type: TypeInteger, Int: 1}},
			{Name: oid("1.3.6.1.2.1.2.2.1.8.1000"), Value: Value{Type: TypeInteger, Int: 2}},
		},
	}
	mustRoundTrip(t, m)
}

func TestTrapV1(t *testing.T) {
	m := &Message{
		Version:      VersionV1,
		Community:    "public",
		PDUType:      PDUTrapV1,
		Enterprise:   oid("1.3.6.1.4.1.9999"),
		AgentAddr:    net.IPv4(10, 0, 0, 1).To4(),
		GenericTrap:  6, // enterpriseSpecific
		SpecificTrap: 1,
		Timestamp:    12345,
		Varbinds: []Varbind{
			{Name: oid("1.3.6.1.4.1.9999.1.1"), Value: Value{Type: TypeOctetString, Str: []byte("hello")}},
		},
	}
	mustRoundTrip(t, m)
}

func TestGenericTrapPatternB(t *testing.T) {
	// A "pattern B" (status-varbind) style alarm, per HLD §5.3.
	m := &Message{
		Version:   VersionV2c,
		Community: "public",
		PDUType:   PDUTrapV2,
		RequestID: 1,
		Varbinds: []Varbind{
			{Name: oid("1.3.6.1.2.1.1.3.0"), Value: Value{Type: TypeTimeTicks, UInt: 100}},
			{Name: oid("1.3.6.1.6.3.1.1.4.1.0"), Value: Value{Type: TypeObjectIdentifier, OID: oid("1.3.6.1.4.1.99999.1.1")}},
			{Name: oid("1.3.6.1.4.1.99999.1.1.1"), Value: Value{Type: TypeInteger, Int: 42}},
			{Name: oid("1.3.6.1.4.1.99999.1.1.2"), Value: Value{Type: TypeInteger, Int: 2}}, // status = major
		},
	}
	mustRoundTrip(t, m)
}

func TestAllValueTypes(t *testing.T) {
	m := &Message{
		Version:   VersionV2c,
		Community: "public",
		PDUType:   PDUTrapV2,
		RequestID: 7,
		Varbinds: []Varbind{
			{Name: oid("1.1"), Value: Value{Type: TypeInteger, Int: -1}},
			{Name: oid("1.2"), Value: Value{Type: TypeOctetString, Str: []byte("octets")}},
			{Name: oid("1.3"), Value: Value{Type: TypeNull}},
			{Name: oid("1.4"), Value: Value{Type: TypeObjectIdentifier, OID: oid("1.3.6.1.2.1")}},
			{Name: oid("1.5"), Value: Value{Type: TypeIPAddress, IP: net.IPv4(198, 51, 100, 7).To4()}},
			{Name: oid("1.6"), Value: Value{Type: TypeCounter32, UInt: 4294967295}},
			{Name: oid("1.7"), Value: Value{Type: TypeGauge32, UInt: 4294967295}},
			{Name: oid("1.8"), Value: Value{Type: TypeTimeTicks, UInt: 0}},
			{Name: oid("1.9"), Value: Value{Type: TypeOpaque, Str: []byte{0xde, 0xad, 0xbe, 0xef}}},
			{Name: oid("1.10"), Value: Value{Type: TypeCounter64, UInt: 18446744073709551615}},
			{Name: oid("1.11"), Value: Value{Type: TypeNoSuchObject}},
			{Name: oid("1.12"), Value: Value{Type: TypeNoSuchInstance}},
			{Name: oid("1.13"), Value: Value{Type: TypeEndOfMibView}},
		},
	}
	mustRoundTrip(t, m)
}

func TestOtherPDUTypes(t *testing.T) {
	for _, pt := range []PDUType{PDUGetRequest, PDUGetNextRequest, PDUGetResponse, PDUSetRequest, PDUGetBulkRequest, PDUInformRequest} {
		m := &Message{
			Version:   VersionV2c,
			Community: "public",
			PDUType:   pt,
			RequestID: 99,
			Varbinds: []Varbind{
				{Name: oid("1.3.6.1.2.1.1.3.0"), Value: Value{Type: TypeNull}},
			},
		}
		mustRoundTrip(t, m)
	}
}

func TestEmptyCommunityAndVarbindList(t *testing.T) {
	m := &Message{
		Version:    VersionV1,
		Community:  "",
		PDUType:    PDUTrapV1,
		Enterprise: oid("1.3.6.1.4.1.1"),
		AgentAddr:  net.IPv4(0, 0, 0, 0).To4(),
		// An explicit empty (non-nil) slice, to match what Decode produces
		// for a zero-length VarBindList — reflect.DeepEqual treats nil and
		// empty-non-nil slices as unequal, which is a test-comparison
		// nuance, not a codec bug.
		Varbinds: []Varbind{},
	}
	mustRoundTrip(t, m)
}

// TestBEIntRoundTrip exercises the minimal two's-complement integer codec
// directly across boundary values where the number of encoded bytes
// changes (0, ±1 around powers of 256, extremes of int64).
func TestBEIntRoundTrip(t *testing.T) {
	values := []int64{
		0, 1, -1, 127, 128, -128, -129, 255, 256, -256,
		32767, 32768, -32768, -32769,
		8388607, 8388608, -8388608, -8388609,
		2147483647, 2147483648, -2147483648, -2147483649,
		9223372036854775807, -9223372036854775808,
	}
	for _, v := range values {
		enc := encodeBEInt(v)
		got := decodeBEInt(enc)
		if got != v {
			t.Errorf("decodeBEInt(encodeBEInt(%d)) = %d (encoded % x)", v, got, enc)
		}
		// Minimality: no leading byte should be redundant.
		if len(enc) > 1 {
			b0, b1 := enc[0], enc[1]
			if (b0 == 0x00 && b1&0x80 == 0) || (b0 == 0xff && b1&0x80 != 0) {
				t.Errorf("encodeBEInt(%d) = % x is not minimal", v, enc)
			}
		}
	}
}

func TestBEUintRoundTrip(t *testing.T) {
	values := []uint64{
		0, 1, 127, 128, 255, 256, 65535, 65536,
		4294967295, 4294967296, 18446744073709551615,
	}
	for _, v := range values {
		enc := encodeBEUint(v)
		got := decodeBEUint(enc)
		if got != v {
			t.Errorf("decodeBEUint(encodeBEUint(%d)) = %d (encoded % x)", v, got, enc)
		}
		// The encoding must never look negative (BER INTEGER content rule).
		if enc[0]&0x80 != 0 {
			t.Errorf("encodeBEUint(%d) = % x has the sign bit set", v, enc)
		}
	}
}

func TestDecode_RejectsTruncatedMessage(t *testing.T) {
	if _, err := Decode([]byte{0x30, 0x7f, 0x02, 0x01, 0x01}); err == nil {
		t.Fatal("Decode of truncated message: want error, got nil")
	}
}

func TestDecode_RejectsNonSequence(t *testing.T) {
	if _, err := Decode([]byte{0x02, 0x01, 0x00}); err == nil {
		t.Fatal("Decode of a bare INTEGER: want error, got nil")
	}
}

func TestOID_HasPrefixAndParse(t *testing.T) {
	full := oid("1.3.6.1.4.1.9999.2.1")
	if !full.HasPrefix(oid("1.3.6.1.4.1.9999")) {
		t.Error("HasPrefix: want true")
	}
	if full.HasPrefix(oid("1.3.6.1.4.1.8888")) {
		t.Error("HasPrefix: want false")
	}
	if full.String() != "1.3.6.1.4.1.9999.2.1" {
		t.Errorf("String() = %q", full.String())
	}
	if _, err := ParseOID(""); err == nil {
		t.Error("ParseOID(\"\"): want error")
	}
	if _, err := ParseOID("1.a.3"); err == nil {
		t.Error("ParseOID with non-numeric arc: want error")
	}
	withDot := oid(".1.3.6.1")
	if withDot.String() != "1.3.6.1" {
		t.Errorf("leading-dot OID = %q, want 1.3.6.1", withDot.String())
	}
}

func TestOID_WithInstance(t *testing.T) {
	base := oid("1.3.6.1.2.1.2.2.1.8")
	got := base.WithInstance(1000)
	if got.String() != "1.3.6.1.2.1.2.2.1.8.1000" {
		t.Errorf("WithInstance(1000) = %q", got.String())
	}
	if base.String() != "1.3.6.1.2.1.2.2.1.8" {
		t.Error("WithInstance mutated the receiver")
	}
}
