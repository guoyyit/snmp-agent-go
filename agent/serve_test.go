package agent

import (
	"context"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guoyyit/snmp-agent-go/config"
	"github.com/guoyyit/snmp-agent-go/mib"
	"github.com/guoyyit/snmp-agent-go/oid"
	"github.com/guoyyit/snmp-agent-go/snmp"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := l.LocalAddr().String()
	l.Close()
	return addr
}

func startServer(t *testing.T, cfg *config.Config, m *mib.MIB, persist func() error) (*Agent, context.CancelFunc) {
	t.Helper()
	a := New(m, cfg, persist)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = a.Serve(ctx) }()
	deadline := time.Now().Add(time.Second)
	for a.LocalAddr() == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if a.LocalAddr() == nil {
		cancel()
		t.Fatal("server did not bind")
	}
	return a, cancel
}

func sendUDP(t *testing.T, addr, community string, pdu *snmp.PDU, wantReply bool) *snmp.Message {
	t.Helper()
	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp4", nil, udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	data, err := snmp.EncodeMessage(&snmp.Message{Version: snmp.Version2c, Community: community, PDU: pdu})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(data); err != nil {
		t.Fatal(err)
	}
	if !wantReply {
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		buf := make([]byte, 2048)
		if _, err := conn.Read(buf); err == nil {
			t.Fatal("unexpected reply")
		}
		return nil
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := snmp.DecodeMessage(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func standardMIB(t *testing.T) *mib.MIB {
	m := mib.New()
	o := func(s string) oid.OID {
		v, err := oid.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	m.Register(mib.Object{OID: o("1.3.6.1.1.0"), Name: "name", Syntax: mib.SyntaxOctetString, Access: mib.AccessReadWrite, MaxOctets: 16}, nil)
	m.Register(mib.Object{OID: o("1.3.6.1.2.0"), Name: "speed", Syntax: mib.SyntaxGauge32, Access: mib.AccessReadWrite}, mib.Gauge32(0))
	m.Register(mib.Object{OID: o("1.3.6.1.3.0"), Name: "packets", Syntax: mib.SyntaxCounter32, Access: mib.AccessReadOnly}, mib.Counter32(0))
	return m
}

func TestUDPGetAndSetEndToEnd(t *testing.T) {
	cfg := config.Default()
	cfg.ListenAddr = freeAddr(t)
	m := standardMIB(t)
	nameOID, _ := oid.Parse("1.3.6.1.1.0")
	speedOID, _ := oid.Parse("1.3.6.1.2.0")

	var persisted atomic.Int32
	a, cancel := startServer(t, cfg, m, func() error { persisted.Add(1); return nil })
	defer cancel()

	resp := sendUDP(t, a.LocalAddr().String(), "public", &snmp.PDU{
		Type: snmp.GetRequest, RequestID: 1,
		VarBinds: []snmp.VarBind{{Name: nameOID, Value: snmp.Null{}}},
	}, true)
	if resp.PDU.ErrorStatus != snmp.NoError {
		t.Fatalf("get error: %+v", resp.PDU)
	}

	resp = sendUDP(t, a.LocalAddr().String(), "private", &snmp.PDU{
		Type: snmp.SetRequest, RequestID: 2,
		VarBinds: []snmp.VarBind{{Name: nameOID, Value: snmp.OctetString("hello")}},
	}, true)
	if resp.PDU.ErrorStatus != snmp.NoError {
		t.Fatalf("set error: %+v", resp.PDU)
	}
	if persisted.Load() != 1 {
		t.Fatalf("persist count = %d", persisted.Load())
	}

	// Read-back reflects the write.
	resp = sendUDP(t, a.LocalAddr().String(), "public", &snmp.PDU{
		Type: snmp.GetRequest, RequestID: 3,
		VarBinds: []snmp.VarBind{{Name: nameOID, Value: snmp.Null{}}, {Name: speedOID, Value: snmp.Null{}}},
	}, true)
	if string(resp.PDU.VarBinds[0].Value.(snmp.OctetString)) != "hello" {
		t.Fatalf("readback = %v", resp.PDU.VarBinds[0].Value)
	}
}

func TestUDPPrivilegeDrop(t *testing.T) {
	cfg := config.Default()
	cfg.ListenAddr = freeAddr(t)
	nameOID, _ := oid.Parse("1.3.6.1.1.0")
	a, cancel := startServer(t, cfg, standardMIB(t), nil)
	defer cancel()

	sendUDP(t, a.LocalAddr().String(), "attacker", &snmp.PDU{
		Type: snmp.GetRequest, RequestID: 1,
		VarBinds: []snmp.VarBind{{Name: nameOID, Value: snmp.Null{}}},
	}, false)
	sendUDP(t, a.LocalAddr().String(), "public", &snmp.PDU{
		Type: snmp.SetRequest, RequestID: 2,
		VarBinds: []snmp.VarBind{{Name: nameOID, Value: snmp.OctetString("x")}},
	}, false)
}

func TestUDPEmptyMIBGetBulk(t *testing.T) {
	cfg := config.Default()
	cfg.ListenAddr = freeAddr(t)
	a, cancel := startServer(t, cfg, mib.New(), nil)
	defer cancel()

	o, _ := oid.Parse("1.3.6.1")
	resp := sendUDP(t, a.LocalAddr().String(), "public", &snmp.PDU{
		Type: snmp.GetBulkRequest, RequestID: 9,
		NonRepeaters: 1, MaxRepetitions: 3,
		VarBinds: []snmp.VarBind{
			{Name: o, Value: snmp.Null{}},
			{Name: o, Value: snmp.Null{}},
		},
	}, true)
	// Deterministic: one endOfMibView per non-repeater, plus one row for the
	// single repeater (round 0 always runs when max-repetitions > 0).
	if len(resp.PDU.VarBinds) != 2 {
		t.Fatalf("empty MIB bulk varbinds = %d, want 2", len(resp.PDU.VarBinds))
	}
	for i, vb := range resp.PDU.VarBinds {
		if ex, ok := vb.Value.(snmp.Exception); !ok || ex != snmp.EndOfMibView {
			t.Fatalf("vb %d = %v, want endOfMibView", i, vb.Value)
		}
	}
}

func TestUDPGetNextWalksWholeMIB(t *testing.T) {
	cfg := config.Default()
	cfg.ListenAddr = freeAddr(t)
	m := standardMIB(t)
	a, cancel := startServer(t, cfg, m, nil)
	defer cancel()

	root, _ := oid.Parse("1.3.6.1")
	cursor := root
	var seen []string
	for {
		resp := sendUDP(t, a.LocalAddr().String(), "public", &snmp.PDU{
			Type: snmp.GetNextRequest, RequestID: int32(len(seen) + 1),
			VarBinds: []snmp.VarBind{{Name: cursor, Value: snmp.Null{}}},
		}, true)
		if resp.PDU.ErrorStatus == snmp.NoSuchName {
			break
		}
		if resp.PDU.ErrorStatus != snmp.NoError {
			t.Fatalf("walk error: %+v", resp.PDU)
		}
		next := resp.PDU.VarBinds[0].Name
		if next.Compare(cursor) <= 0 {
			t.Fatalf("walk did not advance: %s -> %s", cursor, next)
		}
		seen = append(seen, next.String())
		cursor = next
	}
	if len(seen) != 3 {
		t.Fatalf("walk visited %d objects: %v", len(seen), seen)
	}
	want := []string{"1.3.6.1.1.0", "1.3.6.1.2.0", "1.3.6.1.3.0"}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("walk order wrong: %v", seen)
		}
	}
}

func TestRestartRestoresState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	cfg := config.Default()
	cfg.ListenAddr = freeAddr(t)

	nameOID, _ := oid.Parse("1.3.6.1.1.0")

	// First life: set a value and persist.
	m1 := standardMIB(t)
	persist := func() error {
		cfg.Values = make(map[string]config.PersistedValue)
		for k, v := range m1.WritableValues() {
			tag := map[mib.Syntax]string{
				mib.SyntaxInteger32:   "Integer32",
				mib.SyntaxOctetString: "OctetString",
				mib.SyntaxCounter32:   "Counter32",
				mib.SyntaxGauge32:     "Gauge32",
			}[v.Syntax]
			cfg.Values[k] = config.NewPersistedValue(tag, v.Raw)
		}
		return cfg.Save(path)
	}
	a1, cancel1 := startServer(t, cfg, m1, persist)
	sendUDP(t, a1.LocalAddr().String(), "private", &snmp.PDU{
		Type: snmp.SetRequest, RequestID: 1,
		VarBinds: []snmp.VarBind{{Name: nameOID, Value: snmp.OctetString("persisted")}},
	}, true)
	cancel1()
	<-a1.Done()

	// Second life: reload from disk into a freshly built MIB.
	cfg2, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg2.ListenAddr = freeAddr(t)
	m2 := standardMIB(t)
	restored := map[string]mib.StoredValue{}
	for k, v := range cfg2.Values {
		raw, _ := v.DecodeRaw()
		syn := map[string]mib.Syntax{
			"Integer32":   mib.SyntaxInteger32,
			"OctetString": mib.SyntaxOctetString,
			"Counter32":   mib.SyntaxCounter32,
			"Gauge32":     mib.SyntaxGauge32,
		}[v.Syntax]
		restored[k] = mib.StoredValue{Syntax: syn, Raw: raw}
	}
	m2.RestoreValues(restored)

	a2, cancel2 := startServer(t, cfg2, m2, nil)
	defer cancel2()
	resp := sendUDP(t, a2.LocalAddr().String(), "public", &snmp.PDU{
		Type: snmp.GetRequest, RequestID: 2,
		VarBinds: []snmp.VarBind{{Name: nameOID, Value: snmp.Null{}}},
	}, true)
	if string(resp.PDU.VarBinds[0].Value.(snmp.OctetString)) != "persisted" {
		t.Fatalf("after restart value = %v", resp.PDU.VarBinds[0].Value)
	}
}
