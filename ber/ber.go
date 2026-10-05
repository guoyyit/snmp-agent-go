package ber

import "errors"

const (
	TagInteger     byte = 0x02
	TagOctetString byte = 0x04
	TagNull        byte = 0x05
	TagOID         byte = 0x06
	TagSequence    byte = 0x30
)

var (
	ErrTruncated  = errors.New("ber: truncated data")
	ErrBadLength  = errors.New("ber: bad length")
	ErrUnexpected = errors.New("ber: unexpected tag")
)

// TLV is a decoded tag-length-value element.
type TLV struct {
	Tag     byte
	Content []byte
}

// EncodeLen encodes a BER length octet sequence.
func EncodeLen(n int) []byte {
	if n < 0 {
		return []byte{0x80}
	}
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var buf [5]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte(n)
		n >>= 8
	}
	out := make([]byte, 0, 1+len(buf)-i+1)
	out = append(out, byte(0x80|(len(buf)-i)))
	out = append(out, buf[i:]...)
	return out
}

// Encode wraps content with tag and length.
func Encode(tag byte, content []byte) []byte {
	out := make([]byte, 0, len(content)+5)
	out = append(out, tag)
	out = append(out, EncodeLen(len(content))...)
	out = append(out, content...)
	return out
}

// Decode decodes one TLV from b and returns the remaining bytes.
func Decode(b []byte) (tlv TLV, rest []byte, err error) {
	if len(b) < 2 {
		return TLV{}, nil, ErrTruncated
	}
	tag := b[0]
	n := int(b[1])
	pos := 2
	if n&0x80 != 0 {
		numBytes := n & 0x7f
		if numBytes == 0 || numBytes > 4 {
			return TLV{}, nil, ErrBadLength
		}
		if len(b) < pos+numBytes {
			return TLV{}, nil, ErrTruncated
		}
		n = 0
		for i := 0; i < numBytes; i++ {
			n = n<<8 | int(b[pos+i])
		}
		pos += numBytes
	}
	if len(b) < pos+n {
		return TLV{}, nil, ErrTruncated
	}
	return TLV{Tag: tag, Content: b[pos : pos+n]}, b[pos+n:], nil
}

// EncodeInteger encodes a signed integer as INTEGER content.
func EncodeInteger(v int64) []byte {
	var out []byte
	u := uint64(v)
	for u != 0 {
		out = append(out, byte(u))
		u >>= 8
	}
	if len(out) == 0 {
		return []byte{0}
	}
	for len(out) > 1 {
		top, next := out[len(out)-1], out[len(out)-2]
		if top == 0x00 && next&0x80 == 0 {
			out = out[:len(out)-1]
			continue
		}
		if top == 0xff && next&0x80 != 0 {
			out = out[:len(out)-1]
			continue
		}
		break
	}
	top := out[len(out)-1]
	if v < 0 && top&0x80 == 0 {
		out = append(out, 0xff)
	} else if v >= 0 && top&0x80 != 0 {
		out = append(out, 0)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// DecodeInteger decodes INTEGER content into an int64.
func DecodeInteger(b []byte) (int64, error) {
	if len(b) == 0 {
		return 0, ErrBadLength
	}
	neg := b[0]&0x80 != 0
	var v uint64
	if neg {
		v = ^uint64(0)
	}
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return int64(v), nil
}

// EncodeUnsigned encodes a Counter32/Gauge32 value as a non-negative integer.
func EncodeUnsigned(v uint64) []byte {
	if v == 0 {
		return []byte{0}
	}
	var out []byte
	for v > 0 {
		out = append([]byte{byte(v & 0xff)}, out...)
		v >>= 8
	}
	if out[0]&0x80 != 0 {
		out = append([]byte{0}, out...)
	}
	return out
}

// DecodeUnsigned decodes non-negative integer content bounded to 32 bits.
func DecodeUnsigned(b []byte) (uint64, error) {
	v, err := DecodeInteger(b)
	if err != nil {
		return 0, err
	}
	if v < 0 || uint64(v) > 0xffffffff {
		return 0, ErrBadLength
	}
	return uint64(v), nil
}
