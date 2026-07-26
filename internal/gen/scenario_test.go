package gen

import (
	"strings"
	"testing"
	"time"
)

// exampleScenario mirrors plan.html §5.1 Figure 4 verbatim.
const exampleScenario = `
version: 1
devices: 50
interfaces_per_device: 48
snmp: { version: v2c, community: public }
events:
  - kind: linkdown_up
    rate_per_min: 30
    hold: { min: 10s, max: 5m }
  - kind: flap
    devices: 2
    interval: 20s
    count: 12
  - kind: generic_alarm
    trap_oid: 1.3.6.1.4.1.99999.1.1
    rate_per_min: 10
`

func TestLoadScenario_PlanExample(t *testing.T) {
	sc, err := LoadScenario(strings.NewReader(exampleScenario))
	if err != nil {
		t.Fatalf("LoadScenario: %v", err)
	}
	if sc.Devices != 50 || sc.InterfacesPerDevice != 48 {
		t.Errorf("devices=%d interfaces_per_device=%d", sc.Devices, sc.InterfacesPerDevice)
	}
	if sc.SNMP.Version != "v2c" || sc.SNMP.Community != "public" {
		t.Errorf("snmp = %+v", sc.SNMP)
	}
	if len(sc.Events) != 3 {
		t.Fatalf("len(Events) = %d, want 3", len(sc.Events))
	}

	ev0 := sc.Events[0]
	if ev0.Kind != KindLinkDownUp || ev0.RatePerMin != 30 {
		t.Errorf("events[0] = %+v", ev0)
	}
	if ev0.Hold == nil || ev0.Hold.Min.Std() != 10*time.Second || ev0.Hold.Max.Std() != 5*time.Minute {
		t.Errorf("events[0].hold = %+v", ev0.Hold)
	}

	ev1 := sc.Events[1]
	if ev1.Kind != KindFlap || ev1.Devices != 2 || ev1.Count != 12 || ev1.Interval.Std() != 20*time.Second {
		t.Errorf("events[1] = %+v", ev1)
	}

	ev2 := sc.Events[2]
	if ev2.Kind != KindGenericAlarm || ev2.TrapOID != "1.3.6.1.4.1.99999.1.1" || ev2.RatePerMin != 10 {
		t.Errorf("events[2] = %+v", ev2)
	}
}

func TestLoadScenario_DefaultsApplied(t *testing.T) {
	sc, err := LoadScenario(strings.NewReader(`
version: 1
devices: 1
interfaces_per_device: 1
`))
	if err != nil {
		t.Fatalf("LoadScenario: %v", err)
	}
	if sc.SNMP.Version != "v2c" {
		t.Errorf("default snmp.version = %q, want v2c", sc.SNMP.Version)
	}
	if sc.SNMP.Community != "public" {
		t.Errorf("default snmp.community = %q, want public", sc.SNMP.Community)
	}
}

func TestLoadScenario_ValidationErrors(t *testing.T) {
	cases := map[string]string{
		"wrong version":            "version: 2\ndevices: 1\ninterfaces_per_device: 1\n",
		"zero devices":             "version: 1\ndevices: 0\ninterfaces_per_device: 1\n",
		"zero ifaces":              "version: 1\ndevices: 1\ninterfaces_per_device: 0\n",
		"bad snmp version":         "version: 1\ndevices: 1\ninterfaces_per_device: 1\nsnmp: { version: v3 }\n",
		"unknown event kind":       "version: 1\ndevices: 1\ninterfaces_per_device: 1\nevents:\n  - kind: bogus\n",
		"linkdown_up missing hold": "version: 1\ndevices: 1\ninterfaces_per_device: 1\nevents:\n  - kind: linkdown_up\n    rate_per_min: 1\n",
		"linkdown_up zero rate":    "version: 1\ndevices: 1\ninterfaces_per_device: 1\nevents:\n  - kind: linkdown_up\n    rate_per_min: 0\n    hold: { min: 1s, max: 2s }\n",
		"flap too many devices":    "version: 1\ndevices: 2\ninterfaces_per_device: 1\nevents:\n  - kind: flap\n    devices: 5\n    interval: 1s\n    count: 1\n",
		"flap zero count":          "version: 1\ndevices: 2\ninterfaces_per_device: 1\nevents:\n  - kind: flap\n    devices: 1\n    interval: 1s\n    count: 0\n",
		"generic_alarm no oid":     "version: 1\ndevices: 1\ninterfaces_per_device: 1\nevents:\n  - kind: generic_alarm\n    rate_per_min: 1\n",
		"invalid duration":         "version: 1\ndevices: 1\ninterfaces_per_device: 1\nevents:\n  - kind: flap\n    devices: 1\n    interval: not-a-duration\n    count: 1\n",
	}
	for name, yamlSrc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadScenario(strings.NewReader(yamlSrc)); err == nil {
				t.Errorf("LoadScenario(%q): want error, got nil", name)
			}
		})
	}
}
