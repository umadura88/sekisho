// Package event defines sekisho's ingress event — the structured,
// normalized form of one received trap (HLD §2's event layer) — and the
// conversion from a decoded SNMP message into it. The JSON encoding of an
// Event is the golden format of M1a (plan.html §6.1): tests, the future
// REST API, and the ClickHouse rows of M1c all derive from this shape.
package event

import (
	"fmt"
	"net"
	"time"

	"github.com/umadura88/sekisho/internal/snmpcodec"
)

// Varbind is the display form of one varbind. Splitting the OID into base
// and instance, and resolving names/enums, requires the MIB and arrives in
// M1b — here the OID is carried whole and values are rendered raw.
type Varbind struct {
	OID   string `json:"oid"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Event is one normalized ingress event (HLD Figure 12, minus the columns
// that only exist once MIB resolution and storage are in place).
type Event struct {
	EventID    string    `json:"event_id"`
	ReceivedAt time.Time `json:"received_at"`
	SourceAddr string    `json:"source_addr"`
	DeviceID   string    `json:"device_id"`
	Version    string    `json:"version"` // v1 / v2c
	TrapOID    string    `json:"trap_oid"`
	SysUptime  uint64    `json:"sys_uptime"`
	Varbinds   []Varbind `json:"varbinds"`
	RawPDU     []byte    `json:"raw_pdu"` // encoding/json emits base64
}

// Build converts a decoded trap into an Event, applying the RFC 3584
// v1→v2 normalization and the M1a subset of device identity resolution
// (HLD §5.1): the snmpTrapAddress.0 varbind when present, otherwise the
// packet's source address.
//
// For a v1 trap, normalization means synthesizing the v2 varbind shape:
// sysUpTime.0 and snmpTrapOID.0 (derived per RFC 3584) are prepended, and
// the agent-addr field is appended as snmpTrapAddress.0 — preserving the
// device identity that UDP forwarding would otherwise lose (HLD §10.1).
func Build(id string, receivedAt time.Time, sourceAddr string, msg *snmpcodec.Message, rawPDU []byte) (*Event, error) {
	if msg.PDUType != snmpcodec.PDUTrapV1 && msg.PDUType != snmpcodec.PDUTrapV2 {
		return nil, fmt.Errorf("event: PDU type %d is not a trap", msg.PDUType)
	}

	trapOID, ok := msg.TrapOID()
	if !ok {
		return nil, fmt.Errorf("event: trap has no snmpTrapOID varbind")
	}

	version := "v2c"
	varbinds := msg.Varbinds
	if msg.PDUType == snmpcodec.PDUTrapV1 {
		version = "v1"
		varbinds = normalizeV1Varbinds(msg, trapOID)
	}

	uptime, _ := msg.SysUpTime()

	ev := &Event{
		EventID:    id,
		ReceivedAt: receivedAt.UTC(),
		SourceAddr: sourceAddr,
		DeviceID:   resolveDeviceID(varbinds, sourceAddr),
		Version:    version,
		TrapOID:    trapOID.String(),
		SysUptime:  uptime,
		Varbinds:   make([]Varbind, 0, len(varbinds)),
		RawPDU:     rawPDU,
	}
	for _, vb := range varbinds {
		ev.Varbinds = append(ev.Varbinds, Varbind{
			OID:   vb.Name.String(),
			Type:  vb.Value.Type.String(),
			Value: vb.Value.DisplayString(),
		})
	}
	return ev, nil
}

// normalizeV1Varbinds synthesizes the v2 varbind list for a v1 trap per
// RFC 3584 §3.1.
func normalizeV1Varbinds(msg *snmpcodec.Message, trapOID snmpcodec.ObjectIdentifier) []snmpcodec.Varbind {
	out := make([]snmpcodec.Varbind, 0, len(msg.Varbinds)+3)
	out = append(out,
		snmpcodec.Varbind{
			Name:  snmpcodec.OIDSysUpTimeInstance.Clone(),
			Value: snmpcodec.Value{Type: snmpcodec.TypeTimeTicks, UInt: uint64(msg.Timestamp)},
		},
		snmpcodec.Varbind{
			Name:  snmpcodec.OIDSnmpTrapOIDInstance.Clone(),
			Value: snmpcodec.Value{Type: snmpcodec.TypeObjectIdentifier, OID: trapOID},
		},
	)
	out = append(out, msg.Varbinds...)
	if addr := msg.AgentAddr.To4(); addr != nil {
		out = append(out, snmpcodec.Varbind{
			Name:  snmpcodec.OIDSnmpTrapAddressInstance.Clone(),
			Value: snmpcodec.Value{Type: snmpcodec.TypeIPAddress, IP: addr},
		})
	}
	return out
}

// resolveDeviceID implements the M1a subset of HLD §5.1's priority order:
// a non-unspecified snmpTrapAddress.0 varbind wins; otherwise the packet
// source address identifies the device.
func resolveDeviceID(varbinds []snmpcodec.Varbind, sourceAddr string) string {
	for _, vb := range varbinds {
		if vb.Name.Equal(snmpcodec.OIDSnmpTrapAddressInstance) && vb.Value.Type == snmpcodec.TypeIPAddress {
			if ip := vb.Value.IP; ip != nil && !ip.IsUnspecified() {
				return ip.String()
			}
		}
	}
	if host, _, err := net.SplitHostPort(sourceAddr); err == nil {
		return host
	}
	return sourceAddr
}
