package mib

import (
	"errors"
	"sync"
	"testing"

	"github.com/guoyyit/snmp-agent-go/oid"
)

func mustOID(t *testing.T, s string) oid.OID {
	t.Helper()
	o, err := oid.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func o(s string) oid.OID {
	v, err := oid.Parse(s)
	if err != nil {
		panic(err)
	}
	return v
}

func testMIB() *MIB {
	m := New()
	m.Register(Object{OID: o("1.3.6.1.1.0"), Name: "sysDescr", Syntax: SyntaxOctetString, Access: AccessReadWrite, MaxOctets: 8}, nil)
	m.Register(Object{OID: o("1.3.6.1.2.0"), Name: "sysName", Syntax: SyntaxInteger32, Access: AccessReadOnly}, Integer32(1))
	m.Register(Object{OID: o("1.3.6.1.3.0"), Name: "ifInOctets", Syntax: SyntaxCounter32, Access: AccessReadOnly}, Counter32(0))
	m.Register(Object{OID: o("1.3.6.1.4.0"), Name: "ifSpeed", Syntax: SyntaxGauge32, Access: AccessReadWrite}, Gauge32(0))
	return m
}

func TestGetNextTraversal(t *testing.T) {
	m := testMIB()
	cur := oid.OID{}
	var got []string
	for {
		name, _, ok := m.GetNext(cur)
		if !ok {
			break
		}
		got = append(got, name.String())
		cur = name
	}
	want := []string{"1.3.6.1.1.0", "1.3.6.1.2.0", "1.3.6.1.3.0", "1.3.6.1.4.0"}
	if len(got) != len(want) {
		t.Fatalf("traversal = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("position %d = %s, want %s", i, got[i], want[i])
		}
	}
	// GetNext past the end reports end-of-MIB deterministically.
	_, _, ok := m.GetNext(mustOID(t, "1.3.6.1.4.0"))
	if ok {
		t.Fatal("GetNext beyond last object returned a value")
	}
}

func TestAtomicSetRollback(t *testing.T) {
	m := testMIB()
	err := m.ApplySet([]SetItem{
		{Name: mustOID(t, "1.3.6.1.1.0"), Value: OctetString("new")},
		{Name: mustOID(t, "1.3.6.1.2.0"), Value: Integer32(9)}, // read-only
	})
	if !errors.Is(err, ErrReadOnly) {
		t.Fatalf("want ErrReadOnly, got %v", err)
	}
	v, _, _, _ := m.Get(mustOID(t, "1.3.6.1.1.0"))
	if string(v.(OctetString)) != "" {
		t.Fatalf("first varbind leaked despite failed set: %q", v)
	}
}

func TestSetValidation(t *testing.T) {
	m := testMIB()
	err := m.ApplySet([]SetItem{{Name: mustOID(t, "1.3.6.1.9.0"), Value: Integer32(1)}})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	err = m.ApplySet([]SetItem{{Name: mustOID(t, "1.3.6.1.1.0"), Value: OctetString("123456789")}})
	if !errors.Is(err, ErrBadLen) {
		t.Fatalf("want ErrBadLen, got %v", err)
	}
	err = m.ApplySet([]SetItem{{Name: mustOID(t, "1.3.6.1.1.0"), Value: Integer32(1)}})
	if !errors.Is(err, ErrBadType) {
		t.Fatalf("want ErrBadType, got %v", err)
	}
	// Counters are never settable.
	err = m.ApplySet([]SetItem{{Name: mustOID(t, "1.3.6.1.3.0"), Value: Counter32(1)}})
	if !errors.Is(err, ErrReadOnly) {
		t.Fatalf("want ErrReadOnly, got %v", err)
	}
}

func TestCounterWraparound(t *testing.T) {
	m := testMIB()
	oidC := mustOID(t, "1.3.6.1.3.0")
	m.Increment(oidC, 0xffffffff)
	v, syn, _, _ := m.Get(oidC)
	if syn != SyntaxCounter32 || v.(Counter32) != 0xffffffff {
		t.Fatalf("counter = %d syntax %d", v, syn)
	}
	m.Increment(oidC, 1)
	v, _, _, _ = m.Get(oidC)
	if v.(Counter32) != 0 {
		t.Fatalf("counter did not wrap to 0: %d", v)
	}
}

func TestGaugeClampsAndTypesDiffer(t *testing.T) {
	m := testMIB()
	oidG := mustOID(t, "1.3.6.1.4.0")
	m.SetGauge(oidG, 0x1ffffffff)
	v, syn, _, _ := m.Get(oidG)
	if syn != SyntaxGauge32 || v.(Gauge32) != 0xffffffff {
		t.Fatalf("gauge = %d syntax %d", v, syn)
	}
	// Setting a Gauge with a Counter-typed value is rejected.
	err := m.ApplySet([]SetItem{{Name: oidG, Value: Counter32(5)}})
	if !errors.Is(err, ErrBadType) {
		t.Fatalf("counter value accepted for gauge: %v", err)
	}
}

func TestSnapshotRestore(t *testing.T) {
	m := testMIB()
	_ = m.ApplySet([]SetItem{
		{Name: mustOID(t, "1.3.6.1.1.0"), Value: OctetString("host")},
		{Name: mustOID(t, "1.3.6.1.4.0"), Value: Gauge32(100)},
	})
	snap := m.WritableValues()
	if len(snap) != 2 {
		t.Fatalf("snapshot size = %d, want 2", len(snap))
	}
	fresh := testMIB()
	fresh.RestoreValues(snap)
	v, _, _, _ := fresh.Get(mustOID(t, "1.3.6.1.1.0"))
	if string(v.(OctetString)) != "host" {
		t.Fatalf("restored string = %q", v)
	}
	v, _, _, _ = fresh.Get(mustOID(t, "1.3.6.1.4.0"))
	if v.(Gauge32) != 100 {
		t.Fatalf("restored gauge = %d", v)
	}
}

func TestConcurrentSetAtomicity(t *testing.T) {
	m := testMIB()
	a := mustOID(t, "1.3.6.1.1.0")
	b := mustOID(t, "1.3.6.1.4.0")
	stop := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			s := OctetString("ok")
			if i%2 == 0 {
				s = OctetString("00000000")
			}
			_ = m.ApplySet([]SetItem{{Name: a, Value: s}, {Name: b, Value: Gauge32(i % 2)}})
		}
	}()

	for i := 0; i < 1000; i++ {
		snap := m.Snapshot()
		var s string
		var g Gauge32
		for _, nv := range snap {
			switch {
			case nv.Object.OID.Equal(a):
				s = string(nv.Value.(OctetString))
			case nv.Object.OID.Equal(b):
				g = nv.Value.(Gauge32)
			}
		}
		// Every snapshot is a complete state: initial, or one committed phase.
		valid := (s == "" && g == 0) ||
			(s == "ok" && g == 1) ||
			(s == "00000000" && g == 0)
		if !valid {
			t.Fatalf("torn read: string=%q gauge=%d", s, g)
		}
	}
	close(stop)
	wg.Wait()
}
