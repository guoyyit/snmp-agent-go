package main

import "errors"

// PDU tags (context-specific, constructed).
const (
	pduGetRequest     = 0xA0
	pduGetNextRequest = 0xA1
	pduResponse       = 0xA2
	pduSetRequest     = 0xA3
	pduGetBulkRequest = 0xA5
	pduInformRequest  = 0xA6
	pduTrapV2         = 0xA7
)

// Error status codes (RFC 1905).
const (
	errNoError     = 0
	errTooBig      = 1
	errNoSuchName  = 2
	errBadValue    = 3
	errReadOnly    = 4
	errGenErr      = 5
	errNoAccess    = 6
	errWrongType   = 7
	errWrongLength = 8
	errWrongValue  = 10
	errNotWritable = 17
)

// Exception tags used inside response varbinds.
const (
	tagNoSuchObject   = 0x80
	tagNoSuchInstance = 0x81
	tagEndOfMibView   = 0x82
)

// BER tags for values.
const (
	tagInteger     = 0x02
	tagOctetString = 0x04
	tagNull        = 0x05
	tagOID         = 0x06
	tagCounter32   = 0x41
	tagGauge32     = 0x42
	tagTimeTicks   = 0x43
)

var errMalformed = errors.New("snmp: malformed message")

const snmpVersion2c = 1 // SNMPv2c version field value

// varbind is a single (OID, value) pair.
type varbind struct {
	oid   []int
	tag   byte
	value interface{}
}

// pdu is an SNMP protocol data unit. For GetBulkRequest, errorStatus and
// errorIndex hold nonRepeaters and maxRepetitions respectively.
type pdu struct {
	tag         byte
	requestID   int32
	errorStatus int32
	errorIndex  int32
	varbinds    []varbind
}

// decodeMessage parses a full SNMPv2c message. Any deviation from the
// expected structure yields errMalformed; callers must drop such packets.
func decodeMessage(data []byte) (community string, p *pdu, err error) {
	tag, top, rest, err := decodeTLV(data)
	if err != nil || tag != 0x30 || len(rest) != 0 {
		return "", nil, errMalformed
	}
	// version
	tag, verBytes, rest, err := decodeTLV(top)
	if err != nil || tag != tagInteger {
		return "", nil, errMalformed
	}
	ver, err := decodeIntegerValue(verBytes)
	if err != nil || ver != snmpVersion2c {
		return "", nil, errMalformed
	}
	// community
	tag, commBytes, rest, err := decodeTLV(rest)
	if err != nil || tag != tagOctetString {
		return "", nil, errMalformed
	}
	community = string(commBytes)
	// pdu
	tag, pduBytes, rest, err := decodeTLV(rest)
	if err != nil || len(rest) != 0 {
		return "", nil, errMalformed
	}
	switch tag {
	case pduGetRequest, pduGetNextRequest, pduResponse, pduSetRequest,
		pduGetBulkRequest, pduInformRequest, pduTrapV2:
	default:
		return "", nil, errMalformed
	}
	p = &pdu{tag: tag}
	tag, f, rest, err := decodeTLV(pduBytes)
	if err != nil || tag != tagInteger {
		return "", nil, errMalformed
	}
	v, err := decodeIntegerValue(f)
	if err != nil {
		return "", nil, errMalformed
	}
	p.requestID = int32(v)
	tag, f, rest, err = decodeTLV(rest)
	if err != nil || tag != tagInteger {
		return "", nil, errMalformed
	}
	v, err = decodeIntegerValue(f)
	if err != nil {
		return "", nil, errMalformed
	}
	p.errorStatus = int32(v)
	tag, f, rest, err = decodeTLV(rest)
	if err != nil || tag != tagInteger {
		return "", nil, errMalformed
	}
	v, err = decodeIntegerValue(f)
	if err != nil {
		return "", nil, errMalformed
	}
	p.errorIndex = int32(v)
	// varbind list
	tag, vbl, rest, err := decodeTLV(rest)
	if err != nil || tag != 0x30 || len(rest) != 0 {
		return "", nil, errMalformed
	}
	for len(vbl) > 0 {
		var vbBytes []byte
		tag, vbBytes, vbl, err = decodeTLV(vbl)
		if err != nil || tag != 0x30 {
			return "", nil, errMalformed
		}
		vb, err := decodeVarbind(vbBytes)
		if err != nil {
			return "", nil, err
		}
		p.varbinds = append(p.varbinds, vb)
	}
	return community, p, nil
}

// decodeVarbind parses one VarBind SEQUENCE content.
func decodeVarbind(b []byte) (varbind, error) {
	var vb varbind
	tag, oidBytes, rest, err := decodeTLV(b)
	if err != nil || tag != tagOID {
		return vb, errMalformed
	}
	vb.oid, err = decodeOIDValue(oidBytes)
	if err != nil {
		return vb, errMalformed
	}
	tag, valBytes, rest, err := decodeTLV(rest)
	if err != nil || len(rest) != 0 {
		return vb, errMalformed
	}
	vb.tag = tag
	switch tag {
	case tagInteger:
		v, err := decodeIntegerValue(valBytes)
		if err != nil {
			return vb, errMalformed
		}
		vb.value = v
	case tagOctetString:
		vb.value = append([]byte(nil), valBytes...)
	case tagNull, tagNoSuchObject, tagNoSuchInstance, tagEndOfMibView:
		if len(valBytes) != 0 {
			return vb, errMalformed
		}
		vb.value = nil
	case tagOID:
		v, err := decodeOIDValue(valBytes)
		if err != nil {
			return vb, errMalformed
		}
		vb.value = v
	case tagCounter32, tagGauge32, tagTimeTicks:
		v, err := decodeUnsignedValue(valBytes)
		if err != nil {
			return vb, errMalformed
		}
		vb.value = v
	default:
		return vb, errMalformed
	}
	return vb, nil
}

// encodeMessage serializes a message with the given community.
func encodeMessage(community string, p *pdu) []byte {
	var vbList []byte
	for _, vb := range p.varbinds {
		var one []byte
		one = encodeOID(one, tagOID, vb.oid)
		one = encodeValue(one, vb.tag, vb.value)
		vbList = encodeTLV(vbList, 0x30, one)
	}
	var body []byte
	body = encodeInteger(body, tagInteger, int64(p.requestID))
	body = encodeInteger(body, tagInteger, int64(p.errorStatus))
	body = encodeInteger(body, tagInteger, int64(p.errorIndex))
	body = encodeTLV(body, 0x30, vbList)
	var msg []byte
	msg = encodeInteger(msg, tagInteger, snmpVersion2c)
	msg = encodeOctetString(msg, tagOctetString, []byte(community))
	msg = encodeTLV(msg, p.tag, body)
	return encodeTLV(nil, 0x30, msg)
}

// encodeValue appends a varbind value with the given tag.
func encodeValue(dst []byte, tag byte, value interface{}) []byte {
	switch tag {
	case tagInteger:
		v, _ := value.(int64)
		return encodeInteger(dst, tag, v)
	case tagOctetString:
		s, _ := value.([]byte)
		return encodeOctetString(dst, tag, s)
	case tagOID:
		o, _ := value.([]int)
		return encodeOID(dst, tag, o)
	case tagCounter32, tagGauge32, tagTimeTicks:
		v, _ := value.(uint32)
		return encodeUnsigned(dst, tag, v)
	default: // NULL and exception tags carry no content
		return encodeNull(dst, tag)
	}
}
