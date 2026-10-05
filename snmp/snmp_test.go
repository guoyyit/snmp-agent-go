package snmp

import (
	"testing"

	"github.com/guoyyit/snmp-agent-go/oid"
)

func TestEncodeDecodeRoundtrip(t *testing.T) {
	o1, _ := oid.Parse("1.3.6.1.2.1.1.1.0")
	o2, _ := oid.Parse("1.3.6.1.2.1.1.3.0")
	msg := &Message{
		Version:   Version2c,
		Community: "public",
		PDU: &PDU{
			Type:           GetRequest,
			RequestID:      42,
			MaxRepetitions: 0,
			VarBinds: []VarBind{
				{Name: o1, Value: Null{}},
				{Name: o2, Value: Integer32(7)},
			},
		},
	}
	data, err := EncodeMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeMessage(data)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Community != "public" || dec.PDU.RequestID != 42 || dec.PDU.Type != GetRequest {
		t.Fatalf("header mismatch: %+v", dec)
	}
	if len(dec.PDU.VarBinds) != 2 {
		t.Fatalf("varbinds = %d", len(dec.PDU.VarBinds))
	}
	if _, ok := dec.PDU.VarBinds[0].Value.(Null); !ok {
		t.Fatalf("want Null, got %T", dec.PDU.VarBinds[0].Value)
	}
	if v, ok := dec.PDU.VarBinds[1].Value.(Integer32); !ok || v != 7 {
		t.Fatalf("want Integer32(7), got %T %v", dec.PDU.VarBinds[1].Value, v)
	}
}

func TestGetBulkFields(t *testing.T) {
	o, _ := oid.Parse("1.3.6.1")
	msg := &Message{
		Version:   Version2c,
		Community: "public",
		PDU: &PDU{
			Type:           GetBulkRequest,
			RequestID:      -5,
			NonRepeaters:   2,
			MaxRepetitions: 10,
			VarBinds:       []VarBind{{Name: o, Value: Null{}}},
		},
	}
	data, _ := EncodeMessage(msg)
	dec, err := DecodeMessage(data)
	if err != nil {
		t.Fatal(err)
	}
	if dec.PDU.NonRepeaters != 2 || dec.PDU.MaxRepetitions != 10 || dec.PDU.RequestID != -5 {
		t.Fatalf("bulk fields wrong: %+v", dec.PDU)
	}
}

func TestSyntaxTypesPreserved(t *testing.T) {
	o, _ := oid.Parse("1.3.6.1.0")
	for _, v := range []any{Counter32(4294967295), Gauge32(1), OctetString("abc")} {
		data, _ := EncodeMessage(&Message{
			Version:   Version2c,
			Community: "x",
			PDU:       &PDU{Type: SetRequest, RequestID: 1, VarBinds: []VarBind{{Name: o, Value: v}}},
		})
		dec, err := DecodeMessage(data)
		if err != nil {
			t.Fatalf("decode %T: %v", v, err)
		}
		got := dec.PDU.VarBinds[0].Value
		if fmtType(got) != fmtType(v) {
			t.Fatalf("type %T became %T", v, got)
		}
	}
}

func fmtType(v any) string {
	switch v.(type) {
	case Counter32:
		return "c"
	case Gauge32:
		return "g"
	case OctetString:
		return "o"
	}
	return "?"
}

func TestInvalidMessagesDropped(t *testing.T) {
	good, _ := EncodeMessage(&Message{
		Version: Version2c, Community: "public",
		PDU: &PDU{Type: GetRequest, RequestID: 1, VarBinds: []VarBind{{Name: mustOID(t), Value: Null{}}}},
	})
	bad := [][]byte{
		nil,
		{0x30},
		good[:len(good)-1],
		good[1:],
		{0x30, 0x00},
	}
	for i, b := range bad {
		if _, err := DecodeMessage(b); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
}

func TestWrongVersionRejected(t *testing.T) {
	data, _ := EncodeMessage(&Message{
		Version: 0, Community: "public",
		PDU: &PDU{Type: GetRequest, RequestID: 1, VarBinds: []VarBind{{Name: mustOID(t), Value: Null{}}}},
	})
	if _, err := DecodeMessage(data); err == nil {
		t.Fatal("SNMPv1 message accepted")
	}
}

func mustOID(t *testing.T) oid.OID {
	t.Helper()
	o, err := oid.Parse("1.3.6.1")
	if err != nil {
		t.Fatal(err)
	}
	return o
}
