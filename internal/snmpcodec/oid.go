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
