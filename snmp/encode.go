package snmp

import (
	"errors"

	"github.com/guoyyit/snmp-agent-go/ber"
	"github.com/guoyyit/snmp-agent-go/oid"
)

var errUnencodable = errors.New("snmp: unencodable value")

// EncodeMessage encodes an SNMPv2c message.
func EncodeMessage(m *Message) ([]byte, error) {
	body := make([]byte, 0)
	body = append(body, ber.Encode(ber.TagInteger, ber.EncodeInteger(int64(m.Version)))...)
	body = append(body, ber.Encode(ber.TagOctetString, []byte(m.Community))...)
	pdu, err := encodePDU(m.PDU)
	if err != nil {
		return nil, err
	}
	body = append(body, pdu...)
	return ber.Encode(ber.TagSequence, body), nil
}

func encodePDU(p *PDU) ([]byte, error) {
	if p == nil {
		return nil, errUnencodable
	}
	body := make([]byte, 0)
	body = append(body, ber.Encode(ber.TagInteger, ber.EncodeInteger(int64(p.RequestID)))...)

	var field1, field2 int64
	if p.Type == GetBulkRequest {
		field1 = int64(p.NonRepeaters)
		field2 = int64(p.MaxRepetitions)
	} else {
		field1 = int64(p.ErrorStatus)
		field2 = int64(p.ErrorIndex)
	}
	body = append(body, ber.Encode(ber.TagInteger, ber.EncodeInteger(field1))...)
	body = append(body, ber.Encode(ber.TagInteger, ber.EncodeInteger(field2))...)

	varbinds := make([]byte, 0)
	for _, vb := range p.VarBinds {
		encoded, err := encodeVarBind(vb)
		if err != nil {
			return nil, err
		}
		varbinds = append(varbinds, encoded...)
	}
	body = append(body, ber.Encode(ber.TagSequence, varbinds)...)
	return ber.Encode(byte(p.Type), body), nil
}

func encodeVarBind(vb VarBind) ([]byte, error) {
	name, err := vb.Name.EncodeBER()
	if err != nil {
		return nil, err
	}
	body := make([]byte, 0)
	body = append(body, ber.Encode(ber.TagOID, name)...)
	value, err := encodeValue(vb.Value)
	if err != nil {
		return nil, err
	}
	body = append(body, value...)
	return ber.Encode(ber.TagSequence, body), nil
}

func encodeValue(v any) ([]byte, error) {
	switch val := v.(type) {
	case Integer32:
		return ber.Encode(ber.TagInteger, ber.EncodeInteger(int64(val))), nil
	case OctetString:
		return ber.Encode(ber.TagOctetString, []byte(val)), nil
	case Counter32:
		return ber.Encode(0x41, ber.EncodeUnsigned(uint64(val))), nil
	case Gauge32:
		return ber.Encode(0x42, ber.EncodeUnsigned(uint64(val))), nil
	case TimeTicks:
		return ber.Encode(0x43, ber.EncodeUnsigned(uint64(val))), nil
	case oid.OID:
		content, err := val.EncodeBER()
		if err != nil {
			return nil, err
		}
		return ber.Encode(ber.TagOID, content), nil
	case Null:
		return ber.Encode(ber.TagNull, nil), nil
	case Exception:
		return ber.Encode(byte(val), nil), nil
	default:
		return nil, errUnencodable
	}
}
