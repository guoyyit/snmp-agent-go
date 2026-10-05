package main

import "errors"

var errBER = errors.New("ber: malformed data")

// encodeTLV appends a BER TLV with the given tag and value to dst.
func encodeTLV(dst []byte, tag byte, value []byte) []byte {
	dst = append(dst, tag)
	dst = encodeLength(dst, len(value))
	return append(dst, value...)
}

// encodeLength appends a BER length (short or long form).
func encodeLength(dst []byte, n int) []byte {
	if n < 0x80 {
		return append(dst, byte(n))
	}
	var tmp [8]byte
	i := len(tmp)
	for n > 0 {
		i--
		tmp[i] = byte(n)
		n >>= 8
	}
	dst = append(dst, 0x80|byte(len(tmp)-i))
	return append(dst, tmp[i:]...)
}

// encodeInteger appends a signed INTEGER (or application typed integer).
func encodeInteger(dst []byte, tag byte, v int64) []byte {
	var tmp [8]byte
	i := len(tmp)
	for {
		i--
		tmp[i] = byte(v)
		v >>= 8
		// Stop when the remaining value is the sign extension of tmp[i].
		if (v == 0 && tmp[i]&0x80 == 0) || (v == -1 && tmp[i]&0x80 != 0) {
			break
		}
	}
	return encodeTLV(dst, tag, tmp[i:])
}

// encodeUnsigned appends an unsigned 32-bit value with the given tag.
func encodeUnsigned(dst []byte, tag byte, v uint32) []byte {
	var tmp [5]byte
	i := len(tmp)
	for {
		i--
		tmp[i] = byte(v)
		v >>= 8
		if v == 0 {
			if tmp[i]&0x80 != 0 {
				i--
				tmp[i] = 0
			}
			break
		}
	}
	return encodeTLV(dst, tag, tmp[i:])
}

// encodeOctetString appends an OCTET STRING.
func encodeOctetString(dst []byte, tag byte, s []byte) []byte {
	return encodeTLV(dst, tag, s)
}

// encodeOID appends an OBJECT IDENTIFIER.
func encodeOID(dst []byte, tag byte, oid []int) []byte {
	if len(oid) < 2 {
		oid = []int{0, 0}
	}
	var content []byte
	content = encodeBase128(content, oid[0]*40+oid[1])
	for _, n := range oid[2:] {
		content = encodeBase128(content, n)
	}
	return encodeTLV(dst, tag, content)
}

// encodeBase128 appends n in base-128 with continuation bits.
func encodeBase128(dst []byte, n int) []byte {
	var tmp [16]byte
	i := len(tmp)
	i--
	tmp[i] = byte(n & 0x7f)
	n >>= 7
	for n > 0 {
		i--
		tmp[i] = byte(n&0x7f) | 0x80
		n >>= 7
	}
	return append(dst, tmp[i:]...)
}

// encodeNull appends a NULL value with the given tag.
func encodeNull(dst []byte, tag byte) []byte {
	return encodeTLV(dst, tag, nil)
}

// decodeTLV parses one TLV from data, returning tag, value and remaining bytes.
func decodeTLV(data []byte) (tag byte, value, rest []byte, err error) {
	if len(data) < 2 {
		return 0, nil, nil, errBER
	}
	tag = data[0]
	if data[1]&0x80 == 0 {
		n := int(data[1])
		if len(data) < 2+n {
			return 0, nil, nil, errBER
		}
		return tag, data[2 : 2+n], data[2+n:], nil
	}
	numBytes := int(data[1] & 0x7f)
	if numBytes == 0 || numBytes > 4 || len(data) < 2+numBytes {
		return 0, nil, nil, errBER
	}
	n := 0
	for _, b := range data[2 : 2+numBytes] {
		n = n<<8 | int(b)
	}
	off := 2 + numBytes
	if n < 0 || len(data) < off+n {
		return 0, nil, nil, errBER
	}
	return tag, data[off : off+n], data[off+n:], nil
}

// decodeIntegerValue decodes the content bytes of a signed INTEGER.
func decodeIntegerValue(b []byte) (int64, error) {
	if len(b) == 0 || len(b) > 8 {
		return 0, errBER
	}
	var v int64
	if b[0]&0x80 != 0 {
		v = -1
	}
	for _, c := range b {
		v = v<<8 | int64(c)
	}
	return v, nil
}

// decodeUnsignedValue decodes the content bytes of an unsigned 32-bit value.
func decodeUnsignedValue(b []byte) (uint32, error) {
	if len(b) == 0 || len(b) > 5 {
		return 0, errBER
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	if v > 0xffffffff {
		return 0, errBER
	}
	return uint32(v), nil
}

// decodeOIDValue decodes the content bytes of an OBJECT IDENTIFIER.
func decodeOIDValue(b []byte) ([]int, error) {
	if len(b) == 0 {
		return nil, errBER
	}
	var oid []int
	n := 0
	inArc := false
	for _, c := range b {
		inArc = true
		if n > (1 << 57) { // guard against overflow
			return nil, errBER
		}
		n = n<<7 | int(c&0x7f)
		if c&0x80 == 0 {
			if oid == nil {
				// First subidentifier combines arcs 0 and 1.
				switch {
				case n < 40:
					oid = []int{0, n}
				case n < 80:
					oid = []int{1, n - 40}
				default:
					oid = []int{2, n - 80}
				}
			} else {
				oid = append(oid, n)
			}
			n = 0
			inArc = false
		}
	}
	if inArc {
		return nil, errBER
	}
	return oid, nil
}
