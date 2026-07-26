package sanitize

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net"
)

// docRanges are the IPv4 ranges reserved for documentation by RFC 5737.
// Anonymized addresses are drawn from these — they can never collide with
// a real, routable address, and are safe to publish.
var docRanges = []net.IP{
	net.IPv4(198, 51, 100, 0).To4(),
	net.IPv4(203, 0, 113, 0).To4(),
}

// IPMapper deterministically maps real IPv4 addresses to addresses in the
// RFC 5737 documentation ranges, so the same input seed always produces the
// same anonymized capture (plan.html §4.2).
type IPMapper struct {
	seed    string
	mapping map[string]net.IP
	used    map[string]bool
}

// NewIPMapper creates a mapper keyed by seed. The same seed always produces
// the same original->anonymized mapping for a given set of input addresses.
func NewIPMapper(seed string) *IPMapper {
	return &IPMapper{
		seed:    seed,
		mapping: make(map[string]net.IP),
		used:    make(map[string]bool),
	}
}

// Map returns the anonymized address for orig, computing and recording a
// new one deterministically on first use.
func (m *IPMapper) Map(orig net.IP) net.IP {
	ip4 := orig.To4()
	if ip4 == nil {
		ip4 = orig
	}
	key := ip4.String()
	if anon, ok := m.mapping[key]; ok {
		return anon
	}

	h := hmac.New(sha256.New, []byte(m.seed))
	h.Write(ip4)
	sum := h.Sum(nil)
	start := int(sum[0])<<8 | int(sum[1])

	for _, base := range docRanges {
		for probe := 0; probe < 254; probe++ {
			host := byte((start+probe)%254 + 1) // 1..254
			cand := net.IPv4(base[0], base[1], base[2], host)
			candKey := cand.String()
			if !m.used[candKey] {
				m.used[candKey] = true
				m.mapping[key] = cand
				return cand
			}
		}
	}
	// With two /24s (508 usable addresses) this is unreachable for any
	// realistic capture; fail loudly rather than silently reuse an address
	// and merge two distinct real devices into one anonymized identity.
	panic(fmt.Sprintf("sanitize: IP address space exhausted mapping %s", orig))
}

// Report returns a copy of the original->anonymized mapping recorded so
// far, keyed by the original address's string form.
func (m *IPMapper) Report() map[string]net.IP {
	out := make(map[string]net.IP, len(m.mapping))
	for k, v := range m.mapping {
		out[k] = v
	}
	return out
}
