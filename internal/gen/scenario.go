// Package gen implements trapgen's synthetic trap generator (M0c,
// plan.html §5): building a deterministic population of virtual devices
// and interfaces from a scenario, and emitting SNMP trap traffic — either
// following the scenario's own event rates, or as a flat-rate load stream
// for throughput testing.
package gen

import (
	"fmt"
	"io"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration wraps time.Duration so scenario YAML can use strings like "10s"
// or "5m" (time.ParseDuration syntax).
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("gen: invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// Std returns d as a standard time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// DurationRange is an inclusive [Min, Max] duration range, e.g. the "hold"
// time between a linkDown and its matching linkUp.
type DurationRange struct {
	Min Duration `yaml:"min"`
	Max Duration `yaml:"max"`
}

// SNMPConfig configures the SNMP version and community used for generated
// traps.
type SNMPConfig struct {
	Version   string `yaml:"version"` // "v1" or "v2c"
	Community string `yaml:"community"`
}

// EventSpec describes one class of synthetic event. Which fields are
// meaningful depends on Kind:
//   - "linkdown_up": RatePerMin, Hold
//   - "flap":        Devices, Interval, Count
//   - "generic_alarm": RatePerMin, TrapOID
type EventSpec struct {
	Kind       string         `yaml:"kind"`
	RatePerMin float64        `yaml:"rate_per_min"`
	Hold       *DurationRange `yaml:"hold"`
	Devices    int            `yaml:"devices"`
	Interval   Duration       `yaml:"interval"`
	Count      int            `yaml:"count"`
	TrapOID    string         `yaml:"trap_oid"`
}

const (
	KindLinkDownUp   = "linkdown_up"
	KindFlap         = "flap"
	KindGenericAlarm = "generic_alarm"
)

// Scenario is the top-level shape of a scenario YAML file (plan.html §5.1,
// Figure 4).
type Scenario struct {
	Version             int         `yaml:"version"`
	Devices             int         `yaml:"devices"`
	InterfacesPerDevice int         `yaml:"interfaces_per_device"`
	SNMP                SNMPConfig  `yaml:"snmp"`
	Events              []EventSpec `yaml:"events"`
}

// LoadScenario parses and validates a scenario from r.
func LoadScenario(r io.Reader) (*Scenario, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("gen: read scenario: %w", err)
	}
	var sc Scenario
	if err := yaml.Unmarshal(data, &sc); err != nil {
		return nil, fmt.Errorf("gen: parse scenario: %w", err)
	}
	if err := sc.validate(); err != nil {
		return nil, err
	}
	return &sc, nil
}

func (sc *Scenario) validate() error {
	if sc.Version != 1 {
		return fmt.Errorf("gen: unsupported scenario version %d (want 1)", sc.Version)
	}
	if sc.Devices <= 0 {
		return fmt.Errorf("gen: devices must be > 0, got %d", sc.Devices)
	}
	if sc.InterfacesPerDevice <= 0 {
		return fmt.Errorf("gen: interfaces_per_device must be > 0, got %d", sc.InterfacesPerDevice)
	}
	if sc.SNMP.Version == "" {
		sc.SNMP.Version = "v2c"
	}
	if sc.SNMP.Version != "v1" && sc.SNMP.Version != "v2c" {
		return fmt.Errorf("gen: snmp.version must be v1 or v2c, got %q", sc.SNMP.Version)
	}
	if sc.SNMP.Community == "" {
		sc.SNMP.Community = "public"
	}
	for i, ev := range sc.Events {
		switch ev.Kind {
		case KindLinkDownUp:
			if ev.RatePerMin <= 0 {
				return fmt.Errorf("gen: events[%d] (linkdown_up): rate_per_min must be > 0", i)
			}
			if ev.Hold == nil {
				return fmt.Errorf("gen: events[%d] (linkdown_up): hold is required", i)
			}
			if ev.Hold.Min.Std() <= 0 || ev.Hold.Max.Std() < ev.Hold.Min.Std() {
				return fmt.Errorf("gen: events[%d] (linkdown_up): hold.min must be > 0 and hold.max >= hold.min", i)
			}
		case KindFlap:
			if ev.Devices <= 0 {
				return fmt.Errorf("gen: events[%d] (flap): devices must be > 0", i)
			}
			if ev.Devices > sc.Devices {
				return fmt.Errorf("gen: events[%d] (flap): devices (%d) exceeds scenario devices (%d)", i, ev.Devices, sc.Devices)
			}
			if ev.Interval.Std() <= 0 {
				return fmt.Errorf("gen: events[%d] (flap): interval must be > 0", i)
			}
			if ev.Count <= 0 {
				return fmt.Errorf("gen: events[%d] (flap): count must be > 0", i)
			}
		case KindGenericAlarm:
			if ev.RatePerMin <= 0 {
				return fmt.Errorf("gen: events[%d] (generic_alarm): rate_per_min must be > 0", i)
			}
			if ev.TrapOID == "" {
				return fmt.Errorf("gen: events[%d] (generic_alarm): trap_oid is required", i)
			}
		default:
			return fmt.Errorf("gen: events[%d]: unknown kind %q", i, ev.Kind)
		}
	}
	return nil
}
