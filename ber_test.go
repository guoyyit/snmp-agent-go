package main

import (
	"bytes"
	"reflect"
	"testing"
)

func TestIntegerRoundTrip(t *testing.T) {
	for _, v := range []int64{0, 1, 127, 128, 255, 256, -1, -128, -129,
		32767, -32768, 1<<31 - 1, -(1 << 31), 4294967295} {
		buf := encodeInteger(nil, tagInteger, v)
		tag, val, rest, err := decodeTLV(buf)
		if err != nil || tag != tagInteger || len(rest) != 0 {
			t.Fatalf("decodeTLV(%d): tag=%x err=%v", v, tag, err)
		}
		got, err := decodeIntegerValue(val)
		if err != nil || got != v {
			t.Fatalf("round trip %d: got %d err=%v", v, got, err)
		}
	}
}

func TestUnsignedRoundTrip(t *testing.T) {
	for _, v := range []uint32{0, 1, 127, 128, 65535, 1<<31 - 1, 1 << 31,
		0xffffffff} {
		buf := encodeUnsigned(nil, tagCounter32, v)
		tag, val, _, err := decodeTLV(buf)
		if err != nil || tag != tagCounter32 {
			t.Fatalf("decodeTLV(%d): tag=%x err=%v", v, tag, err)
		}
		got, err := decodeUnsignedValue(val)
		if err != nil || got != v {
			t.Fatalf("round trip %d: got %d err=%v", v, got, err)
		}
	}
}

func TestOIDRoundTrip(t *testing.T) {
	oids := [][]int{
		{1, 3, 6, 1, 2, 1, 1, 1, 0},
		{0, 0},
		{2, 999, 3, 128, 16384},
		{1, 3, 6, 1, 4, 1, 53864, 1, 1, 0},
	}
	for _, oid := range oids {
		buf := encodeOID(nil, tagOID, oid)
		tag, val, _, err := decodeTLV(buf)
		if err != nil || tag != tagOID {
			t.Fatalf("decodeTLV(%v): tag=%x err=%v", oid, tag, err)
		}
		got, err := decodeOIDValue(val)
		if err != nil || !reflect.DeepEqual(got, oid) {
			t.Fatalf("round trip %v: got %v err=%v", oid, got, err)
		}
	}
}

func TestDecodeTLVRejectsTruncated(t *testing.T) {
	if _, _, _, err := decodeTLV([]byte{0x30}); err == nil {
		t.Fatal("expected error for truncated header")
	}
	if _, _, _, err := decodeTLV([]byte{0x30, 0x05, 0x01}); err == nil {
		t.Fatal("expected error for truncated value")
	}
	if _, _, _, err := decodeTLV([]byte{0x30, 0x85, 0x01}); err == nil {
		t.Fatal("expected error for oversized length-of-length")
	}
}

func TestLongFormLength(t *testing.T) {
	payload := bytes.Repeat([]byte{0xAB}, 300)
	buf := encodeTLV(nil, 0x30, payload)
	tag, val, rest, err := decodeTLV(buf)
	if err != nil || tag != 0x30 || len(rest) != 0 {
		t.Fatalf("decodeTLV long form: tag=%x err=%v", tag, err)
	}
	if !bytes.Equal(val, payload) {
		t.Fatalf("long form payload mismatch: %d bytes", len(val))
	}
}
