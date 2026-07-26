package sanitize

import (
	"fmt"
	"net"
	"testing"
)

func TestIPMapper_Deterministic(t *testing.T) {
	orig := net.IPv4(10, 0, 0, 42)

	m1 := NewIPMapper("seed-alpha")
	a1 := m1.Map(orig)

	m2 := NewIPMapper("seed-alpha")
	a2 := m2.Map(orig)

	if !a1.Equal(a2) {
		t.Errorf("same seed produced different mappings: %v vs %v", a1, a2)
	}
}

func TestIPMapper_Stable(t *testing.T) {
	m := NewIPMapper("seed")
	orig := net.IPv4(10, 0, 0, 1)
	first := m.Map(orig)
	for i := 0; i < 5; i++ {
		if got := m.Map(orig); !got.Equal(first) {
			t.Fatalf("Map(%v) call %d = %v, want %v (stable within one mapper instance)", orig, i, got, first)
		}
	}
}

func TestIPMapper_OutputInDocumentationRanges(t *testing.T) {
	m := NewIPMapper("seed")
	_, r1, _ := net.ParseCIDR("198.51.100.0/24")
	_, r2, _ := net.ParseCIDR("203.0.113.0/24")

	for i := 1; i <= 60; i++ {
		anon := m.Map(net.IPv4(10, 0, byte(i/256), byte(i%256)))
		if !r1.Contains(anon) && !r2.Contains(anon) {
			t.Errorf("Map produced %v, want an address in %v or %v", anon, r1, r2)
		}
	}
}

func TestIPMapper_NoCollisions(t *testing.T) {
	m := NewIPMapper("seed")
	seen := make(map[string]string) // anon -> orig
	for i := 1; i <= 200; i++ {
		orig := net.IPv4(10, 0, byte(i/256), byte(i%256))
		anon := m.Map(orig).String()
		if prevOrig, ok := seen[anon]; ok && prevOrig != orig.String() {
			t.Fatalf("collision: both %s and %s mapped to %s", prevOrig, orig, anon)
		}
		seen[anon] = orig.String()
	}
}

func TestIPMapper_Report(t *testing.T) {
	m := NewIPMapper("seed")
	orig1 := net.IPv4(10, 0, 0, 1)
	orig2 := net.IPv4(10, 0, 0, 2)
	anon1 := m.Map(orig1)
	anon2 := m.Map(orig2)

	report := m.Report()
	if len(report) != 2 {
		t.Fatalf("Report() has %d entries, want 2", len(report))
	}
	if got := report[orig1.String()]; !got.Equal(anon1) {
		t.Errorf("Report()[%s] = %v, want %v", orig1, got, anon1)
	}
	if got := report[orig2.String()]; !got.Equal(anon2) {
		t.Errorf("Report()[%s] = %v, want %v", orig2, got, anon2)
	}

	// Mutating the returned map must not affect the mapper's own state.
	report[orig1.String()] = net.IPv4(1, 2, 3, 4)
	if got := m.Map(orig1); !got.Equal(anon1) {
		t.Errorf("Report() copy is not independent: Map(%s) = %v after mutating the report", orig1, got)
	}
}

func TestIPMapper_DifferentSeedsDifferMostOfTheTime(t *testing.T) {
	orig := net.IPv4(10, 0, 0, 1)
	different := 0
	for i := 0; i < 20; i++ {
		a := NewIPMapper(fmt.Sprintf("seed-%d", i)).Map(orig)
		b := NewIPMapper(fmt.Sprintf("seed-%d", i+1000)).Map(orig)
		if !a.Equal(b) {
			different++
		}
	}
	if different == 0 {
		t.Error("20 distinct seed pairs all produced the same mapping — seed is not influencing the output")
	}
}
