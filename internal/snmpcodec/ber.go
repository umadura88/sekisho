package snmpcodec

import (
	"encoding/asn1"
	"encoding/binary"
	"fmt"
)

// This file implements the low-level BER tag/length/value framing used by
// the rest of the package. Tag/length parsing is delegated to the standard
// library's encoding/asn1 (via asn1.RawValue), which correctly handles both
// short- and long-form definite lengths; everything SNMP-specific (the
// APPLICATION-tagged types, the CONTEXT-tagged PDU choice, and the integer
// content encoding) is implemented here.
//
// Encoding is always canonical (minimal-length, definite-form): decoding a
// message and re-encoding it is a stable, idempotent operation, even if the
// original bytes used a non-minimal encoding. See plan.html §4.2.

// SNMP application-class tag numbers (RFC 2578 §7.1).
const (
	appIPAddress = 0
	appCounter32 = 1
	appGauge32   = 2
	appTimeTicks = 3
	appOpaque    = 4
	appCounter64 = 6
)

// parseTLV decodes the tag/length/value framing of the first element in b,
// returning the remaining bytes after it.
func parseTLV(b []byte) (asn1.RawValue, []byte, error) {
	var rv asn1.RawValue
	rest, err := asn1.Unmarshal(b, &rv)
	if err != nil {
		return asn1.RawValue{}, nil, err
	}
	return rv, rest, nil
}

// parseElements decodes content as a sequence of consecutive TLV elements,
// as found inside a SEQUENCE's content bytes.
func parseElements(content []byte) ([]asn1.RawValue, error) {
	var out []asn1.RawValue
	for len(content) > 0 {
		rv, rest, err := parseTLV(content)
		if err != nil {
			return nil, err
		}
		out = append(out, rv)
		content = rest
	}
	return out, nil
}

// encodeTLV builds a BER definite-length TLV for one primitive or
// constructed value. tag must be in [0,30]; SNMP never needs the
// high-tag-number form.
func encodeTLV(class int, constructed bool, tag int, content []byte) []byte {
	if tag < 0 || tag > 30 {
		panic(fmt.Sprintf("snmpcodec: tag %d out of range for low-tag-number form", tag))
	}
	ident := byte(class<<6) | byte(tag)
	if constructed {
		ident |= 0x20
	}
	return append(append([]byte{ident}, encodeLength(len(content))...), content...)
}

// encodeLength returns the BER definite-length encoding of n.
func encodeLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var rev []byte
	for n > 0 {
		rev = append(rev, byte(n))
		n >>= 8
	}
	// rev was built least-significant-byte first; the length octets must
	// be most-significant-byte first.
	out := make([]byte, len(rev)+1)
	out[0] = 0x80 | byte(len(rev))
	for i, b := range rev {
		out[len(rev)-i] = b
	}
	return out
}

// concat concatenates byte slices without mutating any of them.
func concat(bs ...[]byte) []byte {
	var total int
	for _, b := range bs {
		total += len(b)
	}
	out := make([]byte, 0, total)
	for _, b := range bs {
		out = append(out, b...)
	}
	return out
}

// encodeBEInt returns the minimal big-endian two's-complement encoding of
// v, as used for the ASN.1 INTEGER type.
func encodeBEInt(v int64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(v))
	i := 0
	for i < 7 {
		if buf[i] == 0x00 && buf[i+1]&0x80 == 0x00 {
			i++
			continue
		}
		if buf[i] == 0xff && buf[i+1]&0x80 == 0x80 {
			i++
			continue
		}
		break
	}
	return buf[i:]
}

// decodeBEInt decodes a minimal big-endian two's-complement INTEGER.
func decodeBEInt(b []byte) int64 {
	if len(b) == 0 {
		return 0
	}
	v := int64(int8(b[0])) // sign-extend the leading byte
	for _, by := range b[1:] {
		v = (v << 8) | int64(by)
	}
	return v
}

// encodeBEUint returns the minimal big-endian encoding of v using the same
// INTEGER content rule, prefixing a 0x00 byte when needed so the value is
// never mistaken for negative. This is how SNMP's "unsigned" application
// types (Counter32, Gauge32, TimeTicks, Counter64) are actually encoded.
func encodeBEUint(v uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, v)
	i := 0
	for i < 7 && buf[i] == 0x00 {
		i++
	}
	b := buf[i:]
	if b[0]&0x80 != 0 {
		b = append([]byte{0x00}, b...)
	}
	return b
}

// decodeBEUint decodes an unsigned big-endian integer (no sign extension).
func decodeBEUint(b []byte) uint64 {
	var v uint64
	for _, by := range b {
		v = (v << 8) | uint64(by)
	}
	return v
}
