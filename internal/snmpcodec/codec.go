// Package snmpcodec implements BER encoding and decoding of SNMPv1 and
// SNMPv2c messages — the Message wrapper, the Trap-PDU / SNMPv2-Trap-PDU /
// InformRequest-PDU and other common PDU shapes, and the varbind value
// types used by trap notifications (HLD §1.1.1, LLD §4.2).
//
// This is a from-scratch implementation deliberately kept free of any
// third-party SNMP library, because it becomes the core of sekisho's
// receiver in M1 (plan.html §4.2) and must not carry external dependencies
// that the receiver would then also depend on.
//
// Decoding never fails on unresolved semantics: unknown varbind value tags
// are the caller's concern (MIB resolution happens above this package).
// What this package guarantees is structural: a syntactically valid BER
// message decodes into a Message, and Message.Encode() of a decoded
// Message reproduces a canonical (but not necessarily byte-identical, if
// the input used a non-minimal length form) re-encoding — decode(encode(m))
// is always equal to m. See codec_test.go for the round-trip contract.
package snmpcodec

import (
	"encoding/asn1"
	"fmt"
	"net"
)

// SNMP message version field values.
const (
	VersionV1  = 0
	VersionV2c = 1
)

// PDUType identifies which PDU variant a Message carries, by its
// context-specific BER tag.
type PDUType int

const (
	PDUGetRequest     PDUType = iota // [0] IMPLICIT SEQUENCE
	PDUGetNextRequest                // [1]
	PDUGetResponse                   // [2] (aka Response)
	PDUSetRequest                    // [3]
	PDUTrapV1                        // [4] SNMPv1 Trap-PDU (distinct shape)
	PDUGetBulkRequest                // [5] (v2c)
	PDUInformRequest                 // [6] (v2c)
	PDUTrapV2                        // [7] SNMPv2-Trap-PDU (v2c)
)

func pduContextTag(t PDUType) (int, error) {
	switch t {
	case PDUGetRequest:
		return 0, nil
	case PDUGetNextRequest:
		return 1, nil
	case PDUGetResponse:
		return 2, nil
	case PDUSetRequest:
		return 3, nil
	case PDUTrapV1:
		return 4, nil
	case PDUGetBulkRequest:
		return 5, nil
	case PDUInformRequest:
		return 6, nil
	case PDUTrapV2:
		return 7, nil
	default:
		return 0, fmt.Errorf("snmpcodec: unknown PDU type %d", t)
	}
}

func pduTypeFromTag(tag int) (PDUType, error) {
	switch tag {
	case 0:
		return PDUGetRequest, nil
	case 1:
		return PDUGetNextRequest, nil
	case 2:
		return PDUGetResponse, nil
	case 3:
		return PDUSetRequest, nil
	case 4:
		return PDUTrapV1, nil
	case 5:
		return PDUGetBulkRequest, nil
	case 6:
		return PDUInformRequest, nil
	case 7:
		return PDUTrapV2, nil
	default:
		return 0, fmt.Errorf("snmpcodec: unknown PDU context tag %d", tag)
	}
}

// ValueType identifies the BER type of a varbind's value.
type ValueType int

const (
	TypeInteger ValueType = iota
	TypeOctetString
	TypeNull
	TypeObjectIdentifier
	TypeIPAddress
	TypeCounter32
	TypeGauge32 // aka Unsigned32
	TypeTimeTicks
	TypeOpaque
	TypeCounter64
	TypeNoSuchObject
	TypeNoSuchInstance
	TypeEndOfMibView
)

// Value is the value half of a varbind. Only the field matching Type is
// meaningful.
type Value struct {
	Type ValueType
	Int  int64            // TypeInteger
	Str  []byte           // TypeOctetString, TypeOpaque
	OID  ObjectIdentifier // TypeObjectIdentifier
	IP   net.IP           // TypeIPAddress (4-byte IPv4)
	UInt uint64           // TypeCounter32, TypeGauge32, TypeTimeTicks, TypeCounter64
}

// Varbind is one (name, value) pair from a VarBindList.
type Varbind struct {
	Name  ObjectIdentifier
	Value Value
}

// Message is a decoded SNMPv1/v2c message: the community-based wrapper
// plus one PDU.
type Message struct {
	Version   int // VersionV1 or VersionV2c
	Community string
	PDUType   PDUType

	// v1 Trap-PDU fields (meaningful only when PDUType == PDUTrapV1).
	Enterprise   ObjectIdentifier
	AgentAddr    net.IP // 4-byte IPv4
	GenericTrap  int
	SpecificTrap int
	Timestamp    uint32 // TimeTicks

	// Common PDU fields (meaningful for every PDUType except PDUTrapV1).
	RequestID   int32
	ErrorStatus int
	ErrorIndex  int

	Varbinds []Varbind
}

// Decode parses an SNMPv1/v2c message from its BER encoding.
func Decode(data []byte) (*Message, error) {
	outer, _, err := parseTLV(data)
	if err != nil {
		return nil, fmt.Errorf("snmpcodec: parse outer sequence: %w", err)
	}
	if outer.Class != asn1.ClassUniversal || outer.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("snmpcodec: unexpected outer tag class=%d tag=%d, want SEQUENCE", outer.Class, outer.Tag)
	}

	elems, err := parseElements(outer.Bytes)
	if err != nil {
		return nil, fmt.Errorf("snmpcodec: parse message elements: %w", err)
	}
	if len(elems) < 3 {
		return nil, fmt.Errorf("snmpcodec: message has %d elements, want 3", len(elems))
	}

	m := &Message{
		Version:   int(decodeBEInt(elems[0].Bytes)),
		Community: string(elems[1].Bytes),
	}

	pduRaw := elems[2]
	if pduRaw.Class != asn1.ClassContextSpecific {
		return nil, fmt.Errorf("snmpcodec: PDU tag class=%d, want context-specific", pduRaw.Class)
	}
	pduType, err := pduTypeFromTag(pduRaw.Tag)
	if err != nil {
		return nil, err
	}
	m.PDUType = pduType

	pduElems, err := parseElements(pduRaw.Bytes)
	if err != nil {
		return nil, fmt.Errorf("snmpcodec: parse PDU elements: %w", err)
	}

	if pduType == PDUTrapV1 {
		if len(pduElems) < 6 {
			return nil, fmt.Errorf("snmpcodec: v1 trap PDU has %d elements, want 6", len(pduElems))
		}
		var ent asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(pduElems[0].FullBytes, &ent); err != nil {
			return nil, fmt.Errorf("snmpcodec: enterprise OID: %w", err)
		}
		m.Enterprise = ObjectIdentifier(ent)

		if pduElems[1].Class != asn1.ClassApplication || pduElems[1].Tag != appIPAddress || len(pduElems[1].Bytes) != 4 {
			return nil, fmt.Errorf("snmpcodec: invalid agent-addr field")
		}
		m.AgentAddr = net.IP(append([]byte(nil), pduElems[1].Bytes...))

		m.GenericTrap = int(decodeBEInt(pduElems[2].Bytes))
		m.SpecificTrap = int(decodeBEInt(pduElems[3].Bytes))
		m.Timestamp = uint32(decodeBEUint(pduElems[4].Bytes))

		vbs, err := decodeVarbindList(pduElems[5])
		if err != nil {
			return nil, err
		}
		m.Varbinds = vbs
		return m, nil
	}

	if len(pduElems) < 4 {
		return nil, fmt.Errorf("snmpcodec: PDU has %d elements, want 4", len(pduElems))
	}
	m.RequestID = int32(decodeBEInt(pduElems[0].Bytes))
	m.ErrorStatus = int(decodeBEInt(pduElems[1].Bytes))
	m.ErrorIndex = int(decodeBEInt(pduElems[2].Bytes))
	vbs, err := decodeVarbindList(pduElems[3])
	if err != nil {
		return nil, err
	}
	m.Varbinds = vbs
	return m, nil
}

func decodeVarbindList(rv asn1.RawValue) ([]Varbind, error) {
	if rv.Class != asn1.ClassUniversal || rv.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("snmpcodec: varbind list tag class=%d tag=%d, want SEQUENCE", rv.Class, rv.Tag)
	}
	pairs, err := parseElements(rv.Bytes)
	if err != nil {
		return nil, err
	}
	vbs := make([]Varbind, 0, len(pairs))
	for _, p := range pairs {
		if p.Class != asn1.ClassUniversal || p.Tag != asn1.TagSequence {
			return nil, fmt.Errorf("snmpcodec: varbind entry tag class=%d tag=%d, want SEQUENCE", p.Class, p.Tag)
		}
		fields, err := parseElements(p.Bytes)
		if err != nil {
			return nil, err
		}
		if len(fields) != 2 {
			return nil, fmt.Errorf("snmpcodec: varbind has %d fields, want 2", len(fields))
		}
		var oid asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(fields[0].FullBytes, &oid); err != nil {
			return nil, fmt.Errorf("snmpcodec: varbind name OID: %w", err)
		}
		val, err := decodeValue(fields[1])
		if err != nil {
			return nil, fmt.Errorf("snmpcodec: varbind %s value: %w", ObjectIdentifier(oid), err)
		}
		vbs = append(vbs, Varbind{Name: ObjectIdentifier(oid), Value: val})
	}
	return vbs, nil
}

func decodeValue(rv asn1.RawValue) (Value, error) {
	switch {
	case rv.Class == asn1.ClassUniversal && rv.Tag == asn1.TagInteger:
		return Value{Type: TypeInteger, Int: decodeBEInt(rv.Bytes)}, nil
	case rv.Class == asn1.ClassUniversal && rv.Tag == asn1.TagOctetString:
		return Value{Type: TypeOctetString, Str: append([]byte(nil), rv.Bytes...)}, nil
	case rv.Class == asn1.ClassUniversal && rv.Tag == asn1.TagNull:
		return Value{Type: TypeNull}, nil
	case rv.Class == asn1.ClassUniversal && rv.Tag == asn1.TagOID:
		var oid asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(rv.FullBytes, &oid); err != nil {
			return Value{}, err
		}
		return Value{Type: TypeObjectIdentifier, OID: ObjectIdentifier(oid)}, nil
	case rv.Class == asn1.ClassApplication && rv.Tag == appIPAddress:
		if len(rv.Bytes) != 4 {
			return Value{}, fmt.Errorf("invalid IpAddress length %d", len(rv.Bytes))
		}
		return Value{Type: TypeIPAddress, IP: net.IP(append([]byte(nil), rv.Bytes...))}, nil
	case rv.Class == asn1.ClassApplication && rv.Tag == appCounter32:
		return Value{Type: TypeCounter32, UInt: decodeBEUint(rv.Bytes)}, nil
	case rv.Class == asn1.ClassApplication && rv.Tag == appGauge32:
		return Value{Type: TypeGauge32, UInt: decodeBEUint(rv.Bytes)}, nil
	case rv.Class == asn1.ClassApplication && rv.Tag == appTimeTicks:
		return Value{Type: TypeTimeTicks, UInt: decodeBEUint(rv.Bytes)}, nil
	case rv.Class == asn1.ClassApplication && rv.Tag == appOpaque:
		return Value{Type: TypeOpaque, Str: append([]byte(nil), rv.Bytes...)}, nil
	case rv.Class == asn1.ClassApplication && rv.Tag == appCounter64:
		return Value{Type: TypeCounter64, UInt: decodeBEUint(rv.Bytes)}, nil
	case rv.Class == asn1.ClassContextSpecific && rv.Tag == 0:
		return Value{Type: TypeNoSuchObject}, nil
	case rv.Class == asn1.ClassContextSpecific && rv.Tag == 1:
		return Value{Type: TypeNoSuchInstance}, nil
	case rv.Class == asn1.ClassContextSpecific && rv.Tag == 2:
		return Value{Type: TypeEndOfMibView}, nil
	default:
		return Value{}, fmt.Errorf("unsupported value class=%d tag=%d", rv.Class, rv.Tag)
	}
}

func encodeValue(v Value) ([]byte, error) {
	switch v.Type {
	case TypeInteger:
		return encodeTLV(asn1.ClassUniversal, false, asn1.TagInteger, encodeBEInt(v.Int)), nil
	case TypeOctetString:
		return encodeTLV(asn1.ClassUniversal, false, asn1.TagOctetString, v.Str), nil
	case TypeNull:
		return encodeTLV(asn1.ClassUniversal, false, asn1.TagNull, nil), nil
	case TypeObjectIdentifier:
		return asn1.Marshal(asn1.ObjectIdentifier(v.OID))
	case TypeIPAddress:
		ip4 := v.IP.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("IpAddress value is not IPv4: %v", v.IP)
		}
		return encodeTLV(asn1.ClassApplication, false, appIPAddress, []byte(ip4)), nil
	case TypeCounter32:
		return encodeTLV(asn1.ClassApplication, false, appCounter32, encodeBEUint(v.UInt)), nil
	case TypeGauge32:
		return encodeTLV(asn1.ClassApplication, false, appGauge32, encodeBEUint(v.UInt)), nil
	case TypeTimeTicks:
		return encodeTLV(asn1.ClassApplication, false, appTimeTicks, encodeBEUint(v.UInt)), nil
	case TypeOpaque:
		return encodeTLV(asn1.ClassApplication, false, appOpaque, v.Str), nil
	case TypeCounter64:
		return encodeTLV(asn1.ClassApplication, false, appCounter64, encodeBEUint(v.UInt)), nil
	case TypeNoSuchObject:
		return encodeTLV(asn1.ClassContextSpecific, false, 0, nil), nil
	case TypeNoSuchInstance:
		return encodeTLV(asn1.ClassContextSpecific, false, 1, nil), nil
	case TypeEndOfMibView:
		return encodeTLV(asn1.ClassContextSpecific, false, 2, nil), nil
	default:
		return nil, fmt.Errorf("unknown value type %d", v.Type)
	}
}

func encodeVarbindList(vbs []Varbind) ([]byte, error) {
	var content []byte
	for _, vb := range vbs {
		nameBytes, err := asn1.Marshal(asn1.ObjectIdentifier(vb.Name))
		if err != nil {
			return nil, fmt.Errorf("snmpcodec: encode varbind name %s: %w", vb.Name, err)
		}
		valBytes, err := encodeValue(vb.Value)
		if err != nil {
			return nil, fmt.Errorf("snmpcodec: encode varbind %s value: %w", vb.Name, err)
		}
		pair := encodeTLV(asn1.ClassUniversal, true, asn1.TagSequence, concat(nameBytes, valBytes))
		content = append(content, pair...)
	}
	return encodeTLV(asn1.ClassUniversal, true, asn1.TagSequence, content), nil
}

// Encode serializes m to its canonical BER encoding.
func (m *Message) Encode() ([]byte, error) {
	versionBytes := encodeTLV(asn1.ClassUniversal, false, asn1.TagInteger, encodeBEInt(int64(m.Version)))
	communityBytes := encodeTLV(asn1.ClassUniversal, false, asn1.TagOctetString, []byte(m.Community))

	vbListBytes, err := encodeVarbindList(m.Varbinds)
	if err != nil {
		return nil, err
	}

	var pduContent []byte
	if m.PDUType == PDUTrapV1 {
		oidBytes, err := asn1.Marshal(asn1.ObjectIdentifier(m.Enterprise))
		if err != nil {
			return nil, fmt.Errorf("snmpcodec: encode enterprise OID: %w", err)
		}
		ip4 := m.AgentAddr.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("snmpcodec: AgentAddr must be IPv4, got %v", m.AgentAddr)
		}
		agentBytes := encodeTLV(asn1.ClassApplication, false, appIPAddress, []byte(ip4))
		genericBytes := encodeTLV(asn1.ClassUniversal, false, asn1.TagInteger, encodeBEInt(int64(m.GenericTrap)))
		specificBytes := encodeTLV(asn1.ClassUniversal, false, asn1.TagInteger, encodeBEInt(int64(m.SpecificTrap)))
		tsBytes := encodeTLV(asn1.ClassApplication, false, appTimeTicks, encodeBEUint(uint64(m.Timestamp)))
		pduContent = concat(oidBytes, agentBytes, genericBytes, specificBytes, tsBytes, vbListBytes)
	} else {
		reqIDBytes := encodeTLV(asn1.ClassUniversal, false, asn1.TagInteger, encodeBEInt(int64(m.RequestID)))
		errStatusBytes := encodeTLV(asn1.ClassUniversal, false, asn1.TagInteger, encodeBEInt(int64(m.ErrorStatus)))
		errIndexBytes := encodeTLV(asn1.ClassUniversal, false, asn1.TagInteger, encodeBEInt(int64(m.ErrorIndex)))
		pduContent = concat(reqIDBytes, errStatusBytes, errIndexBytes, vbListBytes)
	}

	pduTag, err := pduContextTag(m.PDUType)
	if err != nil {
		return nil, err
	}
	pduBytes := encodeTLV(asn1.ClassContextSpecific, true, pduTag, pduContent)

	content := concat(versionBytes, communityBytes, pduBytes)
	return encodeTLV(asn1.ClassUniversal, true, asn1.TagSequence, content), nil
}
