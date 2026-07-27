package snmpcodec

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

// These regression tests reproduce, with synthetic bytes, the three decode
// failure classes observed in a real production capture (2026-07-27):
// long-form lengths with superfluous leading zeros, non-minimal long-form
// lengths, and OID sub-identifiers exceeding int32 — plus SNMPv3 messages,
// which must be rejected with a distinguishable error rather than a
// confusing structural one.

// rewrapOuterLength re-frames a canonically encoded message with a
// deliberately non-minimal outer SEQUENCE length encoding.
func rewrapOuterLength(t *testing.T, canonical []byte, lengthOctets []byte) []byte {
	t.Helper()
	rv, rest, err := parseTLV(canonical)
	if err != nil {
		t.Fatalf("parseTLV(canonical): %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("canonical message has trailing bytes")
	}
	out := append([]byte{0x30}, lengthOctets...)
	return append(out, rv.Bytes...)
}

func simpleTrap(t *testing.T) (*Message, []byte) {
	t.Helper()
	m := &Message{
		Version:   VersionV2c,
		Community: "public",
		PDUType:   PDUTrapV2,
		RequestID: 7,
		Varbinds: []Varbind{
			{Name: oid("1.3.6.1.2.1.1.3.0"), Value: Value{Type: TypeTimeTicks, UInt: 42}},
			{Name: oid("1.3.6.1.6.3.1.1.4.1.0"), Value: Value{Type: TypeObjectIdentifier, OID: oid("1.3.6.1.6.3.1.1.5.3")}},
		},
	}
	enc, err := m.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return m, enc
}

func TestDecode_ToleratesLeadingZeroLength(t *testing.T) {
	want, canonical := simpleTrap(t)
	contentLen := len(canonical) - 2 // canonical is 0x30 <short len> <content>
	if canonical[1] >= 0x80 {
		t.Fatalf("test assumes short-form canonical outer length")
	}

	// 0x83 = long form, 3 length octets; leading zero makes it superfluous.
	loose := rewrapOuterLength(t, canonical, []byte{0x83, 0x00, 0x00, byte(contentLen)})
	got, err := Decode(loose)
	if err != nil {
		t.Fatalf("Decode(leading-zero length): %v", err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("decoded message differs from canonical decode")
	}

	// Re-encoding must produce the canonical form, not preserve the loose one.
	re, err := got.Encode()
	if err != nil {
		t.Fatalf("re-Encode: %v", err)
	}
	if !bytes.Equal(re, canonical) {
		t.Errorf("re-encode is not canonical")
	}
}

func TestDecode_ToleratesNonMinimalLength(t *testing.T) {
	want, canonical := simpleTrap(t)
	contentLen := len(canonical) - 2

	// 0x81 = long form with one octet, for a value < 128: legal BER,
	// non-minimal (DER forbids it; encoding/asn1 rejected it).
	loose := rewrapOuterLength(t, canonical, []byte{0x81, byte(contentLen)})
	got, err := Decode(loose)
	if err != nil {
		t.Fatalf("Decode(non-minimal length): %v", err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("decoded message differs from canonical decode")
	}
}

func TestOID_ArcsBeyondInt32(t *testing.T) {
	// Arcs beyond int32 (e.g. a uint32 timestamp used as an index) appear
	// in real vendor traps and made encoding/asn1 fail with "base 128
	// integer too large".
	big := ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2, 4294967295, 7}
	content, err := encodeOIDContent(big)
	if err != nil {
		t.Fatalf("encodeOIDContent: %v", err)
	}
	back, err := decodeOIDContent(content)
	if err != nil {
		t.Fatalf("decodeOIDContent: %v", err)
	}
	if !back.Equal(big) {
		t.Errorf("round trip = %s, want %s", back, big)
	}

	m := &Message{
		Version: VersionV2c, Community: "public", PDUType: PDUTrapV2, RequestID: 1,
		Varbinds: []Varbind{
			{Name: big, Value: Value{Type: TypeInteger, Int: 1}},
		},
	}
	enc, err := m.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	dec, err := Decode(enc)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !dec.Varbinds[0].Name.Equal(big) {
		t.Errorf("varbind name = %s, want %s", dec.Varbinds[0].Name, big)
	}
}

func TestDecode_V3IsDistinguishable(t *testing.T) {
	// A minimal v3-looking message: SEQUENCE { INTEGER 3, ... }. The codec
	// must reject it with ErrUnsupportedVersion, not a structure error.
	v3 := []byte{0x30, 0x06, 0x02, 0x01, 0x03, 0x04, 0x01, 0x78}
	_, err := Decode(v3)
	if err == nil {
		t.Fatal("Decode(v3): want error, got nil")
	}
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("Decode(v3) error = %v, want ErrUnsupportedVersion", err)
	}
}

func TestDecode_StillRejectsIndefiniteLength(t *testing.T) {
	indef := []byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00}
	if _, err := Decode(indef); err == nil {
		t.Fatal("Decode(indefinite length): want error, got nil")
	}
}
