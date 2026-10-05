package oid

import (
	"errors"
	"strconv"
	"strings"
)

var ErrInvalidOID = errors.New("oid: invalid object identifier")

// OID is a dotted object identifier encoded as a sequence of sub-identifiers.
type OID []uint32

// Parse parses a dotted-decimal OID such as "1.3.6.1.2.1".
func Parse(s string) (OID, error) {
	if s == "" {
		return nil, ErrInvalidOID
	}
	parts := strings.Split(s, ".")
	out := make(OID, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			return nil, ErrInvalidOID
		}
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, ErrInvalidOID
		}
		out = append(out, uint32(n))
	}
	if err := out.validate(); err != nil {
		return nil, err
	}
	return out, nil
}

func (o OID) validate() error {
	if len(o) < 2 {
		return ErrInvalidOID
	}
	if o[0] > 2 {
		return ErrInvalidOID
	}
	if o[0] < 2 && o[1] > 39 {
		return ErrInvalidOID
	}
	return nil
}

// String returns the dotted-decimal representation.
func (o OID) String() string {
	if len(o) == 0 {
		return ""
	}
	var b strings.Builder
	for i, v := range o {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	}
	return b.String()
}

// Compare orders OIDs lexicographically: -1, 0 or 1.
func (o OID) Compare(other OID) int {
	n := len(o)
	if len(other) < n {
		n = len(other)
	}
	for i := 0; i < n; i++ {
		switch {
		case o[i] < other[i]:
			return -1
		case o[i] > other[i]:
			return 1
		}
	}
	switch {
	case len(o) < len(other):
		return -1
	case len(o) > len(other):
		return 1
	}
	return 0
}

// Equal reports whether two OIDs are identical.
func (o OID) Equal(other OID) bool { return o.Compare(other) == 0 }

// HasPrefix reports whether o starts with prefix.
func (o OID) HasPrefix(prefix OID) bool {
	if len(prefix) > len(o) {
		return false
	}
	for i := range prefix {
		if o[i] != prefix[i] {
			return false
		}
	}
	return true
}

// EncodeBER encodes the OID into BER OBJECT-IDENTIFIER content octets.
func (o OID) EncodeBER() ([]byte, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}
	first := 40*o[0] + o[1]
	values := append([]uint64{uint64(first)}, uint64Slice(o[2:])...)
	out := make([]byte, 0, len(o))
	for _, v := range values {
		out = appendBase128(out, v)
	}
	return out, nil
}

func uint64Slice(o OID) []uint64 {
	s := make([]uint64, len(o))
	for i, v := range o {
		s[i] = uint64(v)
	}
	return s
}

func appendBase128(dst []byte, v uint64) []byte {
	shift := 0
	for (v >> uint(shift+7)) != 0 {
		shift += 7
	}
	for ; shift >= 0; shift -= 7 {
		b := byte((v >> uint(shift)) & 0x7f)
		if shift > 0 {
			b |= 0x80
		}
		dst = append(dst, b)
	}
	return dst
}

// DecodeBER decodes an OID from BER OBJECT-IDENTIFIER content octets.
func DecodeBER(b []byte) (OID, error) {
	if len(b) == 0 {
		return nil, ErrInvalidOID
	}
	arcs := make([]uint32, 0, 4)
	var v uint64
	var started bool
	for _, c := range b {
		v = (v << 7) | uint64(c&0x7f)
		started = true
		if c&0x80 == 0 {
			if v > 0xffffffff {
				return nil, ErrInvalidOID
			}
			arcs = append(arcs, uint32(v))
			v, started = 0, false
		}
	}
	if started || len(arcs) == 0 {
		return nil, ErrInvalidOID
	}
	first := arcs[0]
	arcs = arcs[1:]
	switch {
	case first < 40:
		arcs = append([]uint32{0, first}, arcs...)
	case first < 80:
		arcs = append([]uint32{1, first - 40}, arcs...)
	default:
		arcs = append([]uint32{2, first - 80}, arcs...)
	}
	if err := OID(arcs).validate(); err != nil {
		return nil, err
	}
	return OID(arcs), nil
}
