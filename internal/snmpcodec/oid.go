package snmpcodec

import (
	"fmt"
	"strconv"
	"strings"
)

// ObjectIdentifier is a sequence of arcs, e.g. {1,3,6,1,2,1,1,3,0} for
// "1.3.6.1.2.1.1.3.0".
type ObjectIdentifier []int

// String renders the OID in dotted notation.
func (o ObjectIdentifier) String() string {
	parts := make([]string, len(o))
	for i, arc := range o {
		parts[i] = strconv.Itoa(arc)
	}
	return strings.Join(parts, ".")
}

// ParseOID parses a dotted-decimal OID string such as "1.3.6.1.2.1.1.3.0".
// A leading "." is accepted and ignored.
func ParseOID(s string) (ObjectIdentifier, error) {
	s = strings.TrimPrefix(s, ".")
	if s == "" {
		return nil, fmt.Errorf("snmpcodec: empty OID")
	}
	parts := strings.Split(s, ".")
	oid := make(ObjectIdentifier, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("snmpcodec: invalid OID arc %q in %q: %w", p, s, err)
		}
		oid[i] = n
	}
	return oid, nil
}

// WithInstance returns a copy of o with the given instance suffix appended
// — e.g. ifOperStatus.WithInstance(1000) for the ifOperStatus value of
// interface 1000 (HLD §5.1).
func (o ObjectIdentifier) WithInstance(instance ...int) ObjectIdentifier {
	out := make(ObjectIdentifier, len(o)+len(instance))
	copy(out, o)
	copy(out[len(o):], instance)
	return out
}

// HasPrefix reports whether o starts with the given prefix.
func (o ObjectIdentifier) HasPrefix(prefix ObjectIdentifier) bool {
	if len(prefix) > len(o) {
		return false
	}
	for i, arc := range prefix {
		if o[i] != arc {
			return false
		}
	}
	return true
}

// Equal reports whether o and other name the same OID.
func (o ObjectIdentifier) Equal(other ObjectIdentifier) bool {
	if len(o) != len(other) {
		return false
	}
	for i := range o {
		if o[i] != other[i] {
			return false
		}
	}
	return true
}

// Clone returns an independent copy of o.
func (o ObjectIdentifier) Clone() ObjectIdentifier {
	out := make(ObjectIdentifier, len(o))
	copy(out, o)
	return out
}

// decodeOIDContent decodes the content octets of a BER OBJECT IDENTIFIER.
// Unlike encoding/asn1 (which rejects sub-identifiers that do not fit in
// an int32), arcs up to int64 are accepted — production devices encode
// values such as timestamps and indices as single huge arcs.
func decodeOIDContent(b []byte) (ObjectIdentifier, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("snmpcodec: empty OID content")
	}
	var arcs ObjectIdentifier
	var v uint64
	for idx, by := range b {
		if v > (1 << 57) { // next shift would risk exceeding int64
			return nil, fmt.Errorf("snmpcodec: OID sub-identifier exceeds int64")
		}
		v = v<<7 | uint64(by&0x7f)
		if by&0x80 != 0 {
			if idx == len(b)-1 {
				return nil, fmt.Errorf("snmpcodec: truncated OID sub-identifier")
			}
			continue
		}
		if len(arcs) == 0 {
			// The first content sub-identifier packs the first two arcs.
			switch {
			case v < 40:
				arcs = append(arcs, 0, int(v))
			case v < 80:
				arcs = append(arcs, 1, int(v-40))
			default:
				arcs = append(arcs, 2, int(v-80))
			}
		} else {
			arcs = append(arcs, int(v))
		}
		v = 0
	}
	return arcs, nil
}

// encodeOIDContent encodes o's arcs as BER OBJECT IDENTIFIER content
// octets (minimal base-128 form).
func encodeOIDContent(o ObjectIdentifier) ([]byte, error) {
	if len(o) < 2 {
		return nil, fmt.Errorf("snmpcodec: OID %s needs at least two arcs", o)
	}
	if o[0] < 0 || o[0] > 2 || (o[0] < 2 && (o[1] < 0 || o[1] >= 40)) || o[1] < 0 {
		return nil, fmt.Errorf("snmpcodec: invalid leading OID arcs in %s", o)
	}
	var out []byte
	appendArc := func(v uint64) {
		var tmp [10]byte
		i := len(tmp)
		tmp[i-1] = byte(v & 0x7f)
		v >>= 7
		i--
		for v > 0 {
			i--
			tmp[i] = byte(v&0x7f) | 0x80
			v >>= 7
		}
		out = append(out, tmp[i:]...)
	}
	appendArc(uint64(o[0])*40 + uint64(o[1]))
	for _, arc := range o[2:] {
		if arc < 0 {
			return nil, fmt.Errorf("snmpcodec: negative OID arc in %s", o)
		}
		appendArc(uint64(arc))
	}
	return out, nil
}
