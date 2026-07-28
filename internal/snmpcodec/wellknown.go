package snmpcodec

import "fmt"

// Well-known OID instances used across sekisho (all with their .0 instance
// suffix, as they appear in varbind names).
var (
	// OIDSysUpTimeInstance is sysUpTime.0, the mandatory first varbind of
	// an SNMPv2 trap.
	OIDSysUpTimeInstance = ObjectIdentifier{1, 3, 6, 1, 2, 1, 1, 3, 0}
	// OIDSnmpTrapOIDInstance is snmpTrapOID.0, the mandatory second
	// varbind carrying the trap's identity.
	OIDSnmpTrapOIDInstance = ObjectIdentifier{1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0}
	// OIDSnmpTrapAddressInstance is snmpTrapAddress.0 (RFC 3584), carrying
	// the original agent address across v1->v2 conversion and forwarding.
	OIDSnmpTrapAddressInstance = ObjectIdentifier{1, 3, 6, 1, 6, 3, 18, 1, 3, 0}
	// oidSnmpTraps is the prefix under which the six standard v1 generic
	// traps live (coldStart(1) .. egpNeighborLoss(6)).
	oidSnmpTraps = ObjectIdentifier{1, 3, 6, 1, 6, 3, 1, 1, 5}
)

// TrapOID returns the trap's identity OID: the snmpTrapOID.0 varbind value
// for a v2c trap, or the RFC 3584-derived OID for a v1 trap (generic 0..5
// map to the standard trap OIDs; enterpriseSpecific(6) becomes
// enterprise.0.specific). ok is false when the message is a v2c trap
// without a snmpTrapOID.0 varbind, or not a trap at all.
func (m *Message) TrapOID() (ObjectIdentifier, bool) {
	switch m.PDUType {
	case PDUTrapV1:
		if m.GenericTrap >= 0 && m.GenericTrap <= 5 {
			return oidSnmpTraps.WithInstance(m.GenericTrap + 1), true
		}
		return m.Enterprise.WithInstance(0, m.SpecificTrap), true
	case PDUTrapV2, PDUInformRequest:
		for _, vb := range m.Varbinds {
			if vb.Name.Equal(OIDSnmpTrapOIDInstance) && vb.Value.Type == TypeObjectIdentifier {
				return vb.Value.OID, true
			}
		}
		return nil, false
	default:
		return nil, false
	}
}

// SysUpTime returns the trap's uptime ticks: the v1 timestamp field, or
// the sysUpTime.0 varbind of a v2c trap.
func (m *Message) SysUpTime() (uint64, bool) {
	if m.PDUType == PDUTrapV1 {
		return uint64(m.Timestamp), true
	}
	for _, vb := range m.Varbinds {
		if vb.Name.Equal(OIDSysUpTimeInstance) && vb.Value.Type == TypeTimeTicks {
			return vb.Value.UInt, true
		}
	}
	return 0, false
}

// String returns the conventional name of a varbind value type.
func (t ValueType) String() string {
	switch t {
	case TypeInteger:
		return "Integer"
	case TypeOctetString:
		return "OctetString"
	case TypeNull:
		return "Null"
	case TypeObjectIdentifier:
		return "OID"
	case TypeIPAddress:
		return "IpAddress"
	case TypeCounter32:
		return "Counter32"
	case TypeGauge32:
		return "Gauge32"
	case TypeTimeTicks:
		return "TimeTicks"
	case TypeOpaque:
		return "Opaque"
	case TypeCounter64:
		return "Counter64"
	case TypeNoSuchObject:
		return "NoSuchObject"
	case TypeNoSuchInstance:
		return "NoSuchInstance"
	case TypeEndOfMibView:
		return "EndOfMibView"
	default:
		return "Unknown"
	}
}

// DisplayString renders a varbind value as text. Enum resolution (down(2)
// instead of 2) is a MIB concern and happens above this package.
func (v Value) DisplayString() string {
	switch v.Type {
	case TypeInteger:
		return fmt.Sprintf("%d", v.Int)
	case TypeOctetString, TypeOpaque:
		return string(v.Str)
	case TypeObjectIdentifier:
		return v.OID.String()
	case TypeIPAddress:
		if v.IP == nil {
			return ""
		}
		return v.IP.String()
	case TypeCounter32, TypeGauge32, TypeTimeTicks, TypeCounter64:
		return fmt.Sprintf("%d", v.UInt)
	default:
		return ""
	}
}
