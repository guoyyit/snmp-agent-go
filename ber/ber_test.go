package ber

import "testing"

func TestLenEncoding(t *testing.T) {
	cases := map[int][]byte{
		0:   {0x00},
		127: {0x7f},
		128: {0x81, 0x80},
		300: {0x82, 0x01, 0x2c},
	}
	for n, want := range cases {
		got := EncodeLen(n)
		if string(got) != string(want) {
			t.Fatalf("EncodeLen(%d) = % x, want % x", n, got, want)
		}
	}
}

func TestDecodeTLV(t *testing.T) {
	data := Encode(TagInteger, EncodeInteger(42))
	tlv, rest, err := Decode(data)
	if err != nil || len(rest) != 0 || tlv.Tag != TagInteger {
		t.Fatalf("Decode = %+v rest %v err %v", tlv, rest, err)
	}
	v, err := DecodeInteger(tlv.Content)
	if err != nil || v != 42 {
		t.Fatalf("DecodeInteger = %d, %v", v, err)
	}
}

func TestDecodeTruncated(t *testing.T) {
	for _, b := range [][]byte{nil, {0x02}, {0x02, 0x02, 0x01}, {0x04, 0x82, 0x01}, {0x04, 0x85, 0, 0, 0, 0, 0}} {
		if _, _, err := Decode(b); err == nil {
			t.Fatalf("Decode(% x) succeeded, want error", b)
		}
	}
}

func TestIntegerRoundtrip(t *testing.T) {
	vals := []int64{0, 1, -1, 127, 128, -128, -129, 255, 256, -256, 32768, -32768, 2147483647, -2147483648}
	for _, v := range vals {
		got, err := DecodeInteger(EncodeInteger(v))
		if err != nil || got != v {
			t.Fatalf("roundtrip %d = %d, %v", v, got, err)
		}
	}
}

func TestUnsigned(t *testing.T) {
	for _, v := range []uint64{0, 1, 127, 128, 255, 65535, 4294967295} {
		got, err := DecodeUnsigned(EncodeUnsigned(v))
		if err != nil || got != v {
			t.Fatalf("roundtrip %d = %d, %v", v, got, err)
		}
	}
	if _, err := DecodeUnsigned([]byte{0xff}); err == nil {
		t.Fatal("negative content accepted as unsigned")
	}
}
