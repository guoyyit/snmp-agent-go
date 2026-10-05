package snmp

import (
	"errors"
	"fmt"

	"github.com/guoyyit/snmp-agent-go/ber"
	"github.com/guoyyit/snmp-agent-go/oid"
)

var (
	errInvalidMessage = errors.New("snmp: invalid message")
	errInvalidValue   = errors.New("snmp: invalid varbind value")
)

// DecodeMessage decodes one complete SNMPv2c message. Invalid messages
// return an error and must be silently discarded by the caller.
func DecodeMessage(data []byte) (*Message, error) {
	top, rest, err := ber.Decode(data)
	if err != nil || top.Tag != ber.TagSequence || len(rest) != 0 {
		return nil, errInvalidMessage
	}
	buf := top.Content

	verTLV, err := mustField(&buf, ber.TagInteger)
	if err != nil {
		return nil, errInvalidMessage
	}
	version, err := ber.DecodeInteger(verTLV.Content)
	if err != nil || version != Version2c {
		return nil, errInvalidMessage
	}

	commTLV, err := mustField(&buf, ber.TagOctetString)
	if err != nil {
		return nil, errInvalidMessage
	}

	if len(buf) == 0 {
		return nil, errInvalidMessage
	}
	pdu, err := decodePDU(buf)
	if err != nil {
		return nil, err
	}
	return &Message{Version: int(version), Community: string(commTLV.Content), PDU: pdu}, nil
}

// mustField reads exactly one TLV with the expected universal tag from buf
// and advances the cursor.
func mustField(buf *[]byte, tag byte) (ber.TLV, error) {
	tlv, rest, err := ber.Decode(*buf)
	if err != nil || tlv.Tag != tag {
		return ber.TLV{}, errInvalidMessage
	}
	*buf = rest
	return tlv, nil
}

func decodePDU(data []byte) (*PDU, error) {
	tlv, rest, err := ber.Decode(data)
	if err != nil || len(rest) != 0 {
		return nil, errInvalidMessage
	}
	pduType := PDUType(tlv.Tag)
	switch pduType {
	case GetRequest, GetNextRequest, ResponsePDU, SetRequest,
		GetBulkRequest, InformRequest, TrapV2:
	default:
		return nil, errInvalidMessage
	}

	inner, err := decodeSequence(tlv.Content, 4)
	if err != nil {
		return nil, err
	}
	requestID, err := ber.DecodeInteger(inner[0])
	if err != nil || requestID < -2147483648 || requestID > 2147483647 {
		return nil, errInvalidMessage
	}
	field1, err := ber.DecodeInteger(inner[1])
	if err != nil {
		return nil, errInvalidMessage
	}
	field2, err := ber.DecodeInteger(inner[2])
	if err != nil || field2 < 0 {
		return nil, errInvalidMessage
	}

	pdu := &PDU{
		Type:      pduType,
		RequestID: int32(requestID),
	}
	if pduType == GetBulkRequest {
		if field1 < 0 {
			field1 = 0
		}
		pdu.NonRepeaters = int(field1)
		if field2 < 0 {
			field2 = 0
		}
		pdu.MaxRepetitions = int(field2)
	} else {
		pdu.ErrorStatus = ErrorStatus(field1)
		pdu.ErrorIndex = int(field2)
	}

	varbinds, err := decodeVarBindList(inner[3])
	if err != nil {
		return nil, err
	}
	if pduType != GetBulkRequest && pdu.ErrorIndex > len(varbinds) {
		return nil, errInvalidMessage
	}
	pdu.VarBinds = varbinds
	return pdu, nil
}

// decodeFields requires content to be exactly count complete TLV children
// and returns their content slices in order.
func decodeSequence(content []byte, count int) ([][]byte, error) {
	out := make([][]byte, 0, count)
	for len(content) > 0 {
		tlv, rest, err := ber.Decode(content)
		if err != nil {
			return nil, errInvalidMessage
		}
		out = append(out, tlv.Content)
		content = rest
	}
	if len(out) != count {
		return nil, errInvalidMessage
	}
	return out, nil
}

func decodeVarBindList(content []byte) ([]VarBind, error) {
	var out []VarBind
	for len(content) > 0 {
		vbTLV, rest, err := ber.Decode(content)
		if err != nil || vbTLV.Tag != ber.TagSequence {
			return nil, errInvalidMessage
		}
		vb, err := decodeVarBind(vbTLV.Content)
		if err != nil {
			return nil, err
		}
		out = append(out, vb)
		content = rest
	}
	return out, nil
}

func decodeVarBind(content []byte) (VarBind, error) {
	nameTLV, rest, err := ber.Decode(content)
	if err != nil || nameTLV.Tag != ber.TagOID {
		return VarBind{}, errInvalidMessage
	}
	if len(rest) == 0 {
		return VarBind{}, errInvalidMessage
	}
	valTLV, trailing, err := ber.Decode(rest)
	if err != nil || len(trailing) != 0 {
		return VarBind{}, errInvalidMessage
	}
	name, err := oid.DecodeBER(nameTLV.Content)
	if err != nil {
		return VarBind{}, errInvalidMessage
	}
	value, err := decodeValue(valTLV)
	if err != nil {
		return VarBind{}, err
	}
	return VarBind{Name: name, Value: value}, nil
}

func decodeValue(tlv ber.TLV) (any, error) {
	switch tlv.Tag {
	case ber.TagInteger:
		v, err := ber.DecodeInteger(tlv.Content)
		if err != nil || v < -2147483648 || v > 2147483647 {
			return nil, errInvalidValue
		}
		return Integer32(v), nil
	case ber.TagOctetString:
		return OctetString(append([]byte(nil), tlv.Content...)), nil
	case ber.TagNull:
		if len(tlv.Content) != 0 {
			return nil, errInvalidValue
		}
		return Null{}, nil
	case ber.TagOID:
		o, err := oid.DecodeBER(tlv.Content)
		if err != nil {
			return nil, errInvalidValue
		}
		return o, nil
	case 0x41: // Counter32
		v, err := ber.DecodeUnsigned(tlv.Content)
		if err != nil {
			return nil, errInvalidValue
		}
		return Counter32(v), nil
	case 0x42: // Gauge32
		v, err := ber.DecodeUnsigned(tlv.Content)
		if err != nil {
			return nil, errInvalidValue
		}
		return Gauge32(v), nil
	case 0x43: // TimeTicks
		v, err := ber.DecodeUnsigned(tlv.Content)
		if err != nil {
			return nil, errInvalidValue
		}
		return TimeTicks(v), nil
	case byte(NoSuchObject), byte(NoSuchInstance), byte(EndOfMibView):
		if len(tlv.Content) != 0 {
			return nil, errInvalidValue
		}
		return Exception(tlv.Tag), nil
	default:
		return nil, fmt.Errorf("%w: tag 0x%02x", errInvalidValue, tlv.Tag)
	}
}
