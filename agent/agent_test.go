package agent

import (
	"net"
	"testing"

	"github.com/guoyyit/snmp-agent-go/config"
	"github.com/guoyyit/snmp-agent-go/mib"
	"github.com/guoyyit/snmp-agent-go/oid"
	"github.com/guoyyit/snmp-agent-go/snmp"
)

func mustOID(t *testing.T, s string) oid.OID {
	t.Helper()
	o, err := oid.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func testAgent(t *testing.T) (*Agent, map[string]oid.OID) {
	t.Helper()
	m := mib.New()
	oids := map[string]oid.OID{}
	register := func(id, name, syntax string, access mib.Access, max int) {
		o := mustOID(t, id)
		oids[name] = o
		var syn mib.Syntax
		switch syntax {
		case "int":
			syn = mib.SyntaxInteger32
			m.Register(mib.Object{OID: o, Name: name, Syntax: syn, Access: access}, mib.Integer32(0))
		case "str":
			syn = mib.SyntaxOctetString
			m.Register(mib.Object{OID: o, Name: name, Syntax: syn, Access: access, MaxOctets: max}, nil)
		case "counter":
			syn = mib.SyntaxCounter32
			m.Register(mib.Object{OID: o, Name: name, Syntax: syn, Access: access}, mib.Counter32(0))
		case "gauge":
			syn = mib.SyntaxGauge32
			m.Register(mib.Object{OID: o, Name: name, Syntax: syn, Access: access}, mib.Gauge32(0))
		}
	}
	register("1.3.6.1.1.0", "sysDescr", "str", mib.AccessReadWrite, 8)
	register("1.3.6.1.1.5", "sysContact", "str", mib.AccessReadWrite, 0)
	register("1.3.6.1.2.0", "sysUpTime", "int", mib.AccessReadOnly, 0)
	register("1.3.6.1.2.1", "ifIndex.1", "int", mib.AccessReadOnly, 0)
	register("1.3.6.1.2.2", "ifIndex.2", "int", mib.AccessReadOnly, 0)
	register("1.3.6.1.3.1", "ifDescr.1", "str", mib.AccessReadOnly, 0)
	register("1.3.6.1.3.2", "ifDescr.2", "str", mib.AccessReadOnly, 0)
	register("1.3.6.1.4.0", "ifInOctets", "counter", mib.AccessReadOnly, 0)
	register("1.3.6.1.5.0", "ifSpeed", "gauge", mib.AccessReadWrite, 0)

	cfg := config.Default()
	return New(m, cfg, nil), oids
}

func roundTrip(t *testing.T, a *Agent, community string, pdu *snmp.PDU) *snmp.Message {
	t.Helper()
	msg := &snmp.Message{Version: snmp.Version2c, Community: community, PDU: pdu}
	data, err := snmp.EncodeMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	resp := a.handle(data, nil)
	if resp == nil {
		t.Fatal("expected a response, got nil")
	}
	dec, err := snmp.DecodeMessage(resp)
	if err != nil {
		t.Fatal(err)
	}
	return dec
}

func TestGetSuccessAndNoSuchName(t *testing.T) {
	a, oids := testAgent(t)
	resp := roundTrip(t, a, "public", &snmp.PDU{
		Type: snmp.GetRequest, RequestID: 1,
		VarBinds: []snmp.VarBind{{Name: oids["sysDescr"], Value: snmp.Null{}}},
	})
	if resp.PDU.ErrorStatus != snmp.NoError || len(resp.PDU.VarBinds) != 1 {
		t.Fatalf("get failed: %+v", resp.PDU)
	}

	resp = roundTrip(t, a, "public", &snmp.PDU{
		Type: snmp.GetRequest, RequestID: 2,
		VarBinds: []snmp.VarBind{
			{Name: oids["sysDescr"], Value: snmp.Null{}},
			{Name: mustOID(t, "2.999.999"), Value: snmp.Null{}},
		},
	})
	if resp.PDU.ErrorStatus != snmp.NoSuchName || resp.PDU.ErrorIndex != 2 {
		t.Fatalf("want noSuchName index 2, got %+v", resp.PDU)
	}
}

func TestGetNextWalksAndEnds(t *testing.T) {
	a, oids := testAgent(t)
	resp := roundTrip(t, a, "public", &snmp.PDU{
		Type: snmp.GetNextRequest, RequestID: 1,
		VarBinds: []snmp.VarBind{{Name: mustOID(t, "1.3.6.1.1"), Value: snmp.Null{}}},
	})
	if !resp.PDU.VarBinds[0].Name.Equal(oids["sysDescr"]) {
		t.Fatalf("getnext returned %s", resp.PDU.VarBinds[0].Name)
	}

	// Querying past the last object is an error for GetNext.
	resp = roundTrip(t, a, "public", &snmp.PDU{
		Type: snmp.GetNextRequest, RequestID: 2,
		VarBinds: []snmp.VarBind{{Name: mustOID(t, "1.3.6.1.5.0"), Value: snmp.Null{}}},
	})
	if resp.PDU.ErrorStatus != snmp.NoSuchName || resp.PDU.ErrorIndex != 1 {
		t.Fatalf("want end noSuchName, got %+v", resp.PDU)
	}
}

func TestGetBulkNonRepeatersAndRepetitions(t *testing.T) {
	a, oids := testAgent(t)
	resp := roundTrip(t, a, "public", &snmp.PDU{
		Type: snmp.GetBulkRequest, RequestID: 1,
		NonRepeaters:   1,
		MaxRepetitions: 2,
		VarBinds: []snmp.VarBind{
			{Name: oids["sysContact"], Value: snmp.Null{}},
			{Name: mustOID(t, "1.3.6.1.2"), Value: snmp.Null{}},
			{Name: mustOID(t, "1.3.6.1.3"), Value: snmp.Null{}},
		},
	})
	want := []string{
		"1.3.6.1.2.0", // non-repeater: next(sysContact=1.3.6.1.1.5)
		"1.3.6.1.2.0", // repetition 1, col A (next of 1.3.6.1.2)
		"1.3.6.1.3.1", // repetition 1, col B (next of 1.3.6.1.3)
		"1.3.6.1.2.1", // repetition 2, col A
		"1.3.6.1.3.2", // repetition 2, col B
	}
	if len(resp.PDU.VarBinds) != len(want) {
		t.Fatalf("varbinds = %d, want %d (%+v)", len(resp.PDU.VarBinds), len(want), resp.PDU.VarBinds)
	}
	for i, w := range want {
		if resp.PDU.VarBinds[i].Name.String() != w {
			t.Fatalf("vb %d = %s, want %s", i, resp.PDU.VarBinds[i].Name, w)
		}
	}
}

func TestGetBulkEndOfMibDeterministic(t *testing.T) {
	a, _ := testAgent(t)
	resp := roundTrip(t, a, "public", &snmp.PDU{
		Type: snmp.GetBulkRequest, RequestID: 1,
		NonRepeaters: 0, MaxRepetitions: 3,
		VarBinds: []snmp.VarBind{{Name: mustOID(t, "2.999"), Value: snmp.Null{}}},
	})
	if len(resp.PDU.VarBinds) != 1 {
		t.Fatalf("want one endOfMibView, got %d", len(resp.PDU.VarBinds))
	}
	if ex, ok := resp.PDU.VarBinds[0].Value.(snmp.Exception); !ok || ex != snmp.EndOfMibView {
		t.Fatalf("want endOfMibView, got %T %v", resp.PDU.VarBinds[0].Value, resp.PDU.VarBinds[0].Value)
	}
}

func TestGetBulkRespectsSizeLimit(t *testing.T) {
	a, _ := testAgent(t)
	// Two repeaters over a long table region with a tiny budget: the number
	// of returned varbinds must be limited, never exceeding the cap.
	respPDU := bulkPDU(&snmp.PDU{
		Type: snmp.GetBulkRequest, RequestID: 1,
		NonRepeaters: 0, MaxRepetitions: 1000,
		VarBinds: []snmp.VarBind{
			{Name: mustOID(t, "1.3.6.1.1"), Value: snmp.Null{}},
			{Name: mustOID(t, "1.3.6.1.2"), Value: snmp.Null{}},
		},
	}, a.mib, "public", 80)
	msg := &snmp.Message{Version: snmp.Version2c, Community: "public", PDU: respPDU}
	data, err := snmp.EncodeMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > 80 {
		t.Fatalf("bulk response %d bytes exceeds 80", len(data))
	}
	if len(respPDU.VarBinds) == 0 {
		t.Fatal("expected at least one varbind to fit")
	}
}

func TestSetSuccessAndPersist(t *testing.T) {
	a, oids := testAgent(t)
	called := false
	a.persist = func() error { called = true; return nil }
	resp := roundTrip(t, a, "private", &snmp.PDU{
		Type: snmp.SetRequest, RequestID: 1,
		VarBinds: []snmp.VarBind{
			{Name: oids["sysDescr"], Value: snmp.OctetString("host")},
			{Name: oids["ifSpeed"], Value: snmp.Gauge32(1000)},
		},
	})
	if resp.PDU.ErrorStatus != snmp.NoError {
		t.Fatalf("set failed: %+v", resp.PDU)
	}
	if !called {
		t.Fatal("persist hook not invoked after successful set")
	}
	v, _, _, ok := a.mib.Get(oids["ifSpeed"])
	if !ok || v.(mib.Gauge32) != 1000 {
		t.Fatalf("gauge not set: %v", v)
	}
}

func TestSetAtomicRollbackAndErrorIndex(t *testing.T) {
	a, oids := testAgent(t)
	resp := roundTrip(t, a, "private", &snmp.PDU{
		Type: snmp.SetRequest, RequestID: 1,
		VarBinds: []snmp.VarBind{
			{Name: oids["sysDescr"], Value: snmp.OctetString("x")},
			{Name: oids["sysUpTime"], Value: snmp.Integer32(1)}, // read-only
		},
	})
	if resp.PDU.ErrorStatus != snmp.ReadOnly || resp.PDU.ErrorIndex != 2 {
		t.Fatalf("want readOnly index 2, got %+v", resp.PDU)
	}
	v, _, _, _ := a.mib.Get(oids["sysDescr"])
	if len(v.(mib.OctetString)) != 0 {
		t.Fatalf("rollback leaked: %q", v)
	}

	// Wrong type -> badValue with index.
	resp = roundTrip(t, a, "private", &snmp.PDU{
		Type: snmp.SetRequest, RequestID: 2,
		VarBinds: []snmp.VarBind{
			{Name: oids["ifSpeed"], Value: snmp.Counter32(1)},
		},
	})
	if resp.PDU.ErrorStatus != snmp.BadValue || resp.PDU.ErrorIndex != 1 {
		t.Fatalf("want badValue index 1, got %+v", resp.PDU)
	}
}

func TestAccessControlDrops(t *testing.T) {
	a, oids := testAgent(t)
	msg := &snmp.Message{Version: snmp.Version2c, Community: "wrong", PDU: &snmp.PDU{
		Type: snmp.GetRequest, RequestID: 1,
		VarBinds: []snmp.VarBind{{Name: oids["sysDescr"], Value: snmp.Null{}}},
	}}
	data, _ := snmp.EncodeMessage(msg)
	if out := a.handle(data, nil); out != nil {
		t.Fatal("unknown community must not get a response")
	}

	// Read-only community issuing a Set is silently dropped.
	msg.Community = "public"
	msg.PDU.Type = snmp.SetRequest
	data, _ = snmp.EncodeMessage(msg)
	if out := a.handle(data, nil); out != nil {
		t.Fatal("read-only community must not set")
	}
}

func TestInformAckAndGarbageDropped(t *testing.T) {
	a, oids := testAgent(t)
	resp := roundTrip(t, a, "public", &snmp.PDU{
		Type: snmp.InformRequest, RequestID: 77,
		VarBinds: []snmp.VarBind{{Name: oids["sysUpTime"], Value: snmp.TimeTicks(1)}},
	})
	if resp.PDU.Type != snmp.ResponsePDU || resp.PDU.RequestID != 77 {
		t.Fatalf("inform not echoed as response: %+v", resp.PDU)
	}

	for _, garbage := range [][]byte{{0x30, 0x05, 0x02, 0x01, 0x01}, {0xff}, nil} {
		if out := a.handle(garbage, nil); out != nil {
			t.Fatalf("garbage produced a response: % x", out)
		}
	}
}

func TestPeerObserverFiresOnlyForAuthorized(t *testing.T) {
	a, oids := testAgent(t)
	var peers []string
	a.SetPeerObserver(func(addr string) { peers = append(peers, addr) })

	src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	good, _ := snmp.EncodeMessage(&snmp.Message{Version: snmp.Version2c, Community: "public",
		PDU: &snmp.PDU{Type: snmp.GetRequest, RequestID: 1,
			VarBinds: []snmp.VarBind{{Name: oids["sysDescr"], Value: snmp.Null{}}}}})
	bad, _ := snmp.EncodeMessage(&snmp.Message{Version: snmp.Version2c, Community: "nope",
		PDU: &snmp.PDU{Type: snmp.GetRequest, RequestID: 1,
			VarBinds: []snmp.VarBind{{Name: oids["sysDescr"], Value: snmp.Null{}}}}})

	if a.handle(good, src) == nil {
		t.Fatal("authorized request produced no response")
	}
	if a.handle(bad, src) != nil {
		t.Fatal("unauthorized request produced a response")
	}
	if len(peers) != 1 || peers[0] != src.String() {
		t.Fatalf("peers observed = %v", peers)
	}
}
