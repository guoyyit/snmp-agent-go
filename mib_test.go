package main

import (
	"fmt"
	"sync"
	"testing"
)

func testStore() *mibStore {
	s := newMIBStore()
	s.add(&mibObject{oid: []int{1, 3, 6, 1, 2, 1, 1, 1, 0},
		tag: tagOctetString, strVal: []byte("descr")})
	s.add(&mibObject{oid: []int{1, 3, 6, 1, 2, 1, 1, 3, 0},
		tag: tagTimeTicks})
	s.add(&mibObject{oid: []int{1, 3, 6, 1, 2, 1, 1, 5, 0},
		tag: tagOctetString, writable: true, maxLen: 8,
		strVal: []byte("name")})
	s.add(&mibObject{oid: []int{1, 3, 6, 1, 4, 1, 1, 1, 0},
		tag: tagCounter32})
	s.add(&mibObject{oid: []int{1, 3, 6, 1, 4, 1, 1, 2, 0},
		tag: tagGauge32, writable: true})
	return s
}

func TestGetNextWalkBoundaries(t *testing.T) {
	s := testStore()
	// Before the first object.
	vb, ok := s.nextVarbind([]int{0, 1})
	if !ok || oidCompare(vb.oid, []int{1, 3, 6, 1, 2, 1, 1, 1, 0}) != 0 {
		t.Fatalf("first next: %v %v", vb.oid, ok)
	}
	// Exact object advances to its successor.
	vb, ok = s.nextVarbind([]int{1, 3, 6, 1, 2, 1, 1, 1, 0})
	if !ok || oidCompare(vb.oid, []int{1, 3, 6, 1, 2, 1, 1, 3, 0}) != 0 {
		t.Fatalf("successor: %v %v", vb.oid, ok)
	}
	// Nonexistent OID between objects lands on the next real one.
	vb, ok = s.nextVarbind([]int{1, 3, 6, 1, 2, 1, 1, 2, 0})
	if !ok || oidCompare(vb.oid, []int{1, 3, 6, 1, 2, 1, 1, 3, 0}) != 0 {
		t.Fatalf("gap: %v %v", vb.oid, ok)
	}
	// Past the last object: end of MIB.
	if _, ok = s.nextVarbind([]int{9, 9}); ok {
		t.Fatal("expected end of MIB past last object")
	}
	// Full walk visits every object exactly once, in order.
	var walked [][]int
	cur := []int{0}
	for {
		vb, ok := s.nextVarbind(cur)
		if !ok {
			break
		}
		walked = append(walked, vb.oid)
		cur = vb.oid
	}
	if len(walked) != len(s.objects) {
		t.Fatalf("walked %d objects, want %d", len(walked), len(s.objects))
	}
	for i := 1; i < len(walked); i++ {
		if oidCompare(walked[i-1], walked[i]) >= 0 {
			t.Fatalf("walk order broken at %d: %v >= %v", i, walked[i-1], walked[i])
		}
	}
}

func TestSetAtomicAllOrNothing(t *testing.T) {
	s := testStore()
	vbs := []varbind{
		{oid: []int{1, 3, 6, 1, 2, 1, 1, 5, 0}, tag: tagOctetString,
			value: []byte("new")},
		{oid: []int{1, 3, 6, 1, 2, 1, 1, 1, 0}, tag: tagOctetString,
			value: []byte("x")}, // read-only object
	}
	status, index := s.set(vbs)
	if status != errNotWritable || index != 2 {
		t.Fatalf("status=%d index=%d, want notWritable@2", status, index)
	}
	// The first (valid) varbind must NOT have been applied.
	got, _ := s.getVarbind([]int{1, 3, 6, 1, 2, 1, 1, 5, 0})
	if string(got.value.([]byte)) != "name" {
		t.Fatalf("partial set leaked: %q", got.value)
	}
}

func TestSetValidation(t *testing.T) {
	s := testStore()
	name := []int{1, 3, 6, 1, 2, 1, 1, 5, 0}
	// Wrong type.
	st, idx := s.set([]varbind{{oid: name, tag: tagInteger, value: int64(1)}})
	if st != errWrongType || idx != 1 {
		t.Fatalf("wrong type: st=%d idx=%d", st, idx)
	}
	// Too long.
	st, _ = s.set([]varbind{{oid: name, tag: tagOctetString,
		value: []byte("0123456789")}})
	if st != errWrongLength {
		t.Fatalf("wrong length: st=%d", st)
	}
	// Nonexistent object.
	st, _ = s.set([]varbind{{oid: []int{1, 2, 3}, tag: tagInteger,
		value: int64(1)}})
	if st != errNoSuchName {
		t.Fatalf("nonexistent: st=%d", st)
	}
	// Valid set applies.
	st, _ = s.set([]varbind{{oid: name, tag: tagOctetString,
		value: []byte("ok")}})
	if st != errNoError {
		t.Fatalf("valid set: st=%d", st)
	}
}

func TestCounterWrapsGaugeClamps(t *testing.T) {
	s := testStore()
	counter := []int{1, 3, 6, 1, 4, 1, 1, 1, 0}
	gauge := []int{1, 3, 6, 1, 4, 1, 1, 2, 0}
	s.increment(counter, 0xfffffffe)
	s.increment(counter, 5) // wraps past 2^32-1
	vb, _ := s.getVarbind(counter)
	if got := vb.value.(uint32); got != 3 {
		t.Fatalf("counter: got %d, want 3 (wrapped)", got)
	}
	s.increment(gauge, 0xfffffffe)
	s.increment(gauge, 5) // clamps at max
	vb, _ = s.getVarbind(gauge)
	if got := vb.value.(uint32); got != 0xffffffff {
		t.Fatalf("gauge: got %#x, want 0xffffffff (clamped)", got)
	}
}

func TestConcurrentReadersSeeConsistentState(t *testing.T) {
	s := testStore()
	a := []int{1, 3, 6, 1, 2, 1, 1, 5, 0}
	b := []int{1, 3, 6, 1, 4, 1, 1, 2, 0}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	// Writer alternates the pair ("x",1) <-> ("y",2) atomically.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			str := []byte("x")
			var num uint32 = 1
			if i%2 == 1 {
				str = []byte("y")
				num = 2
			}
			s.set([]varbind{
				{oid: a, tag: tagOctetString, value: str},
				{oid: b, tag: tagGauge32, value: num},
			})
		}
		close(stop)
	}()
	// Readers must only ever observe matching pairs.
	var err error
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			pair := s.getMany([][]int{a, b})
			str := string(pair[0].value.([]byte))
			num := pair[1].value.(uint32)
			if (str == "x" && num != 1) || (str == "y" && num != 2) ||
				(str != "x" && str != "y" && str != "name") {
				err = fmt.Errorf("torn read: %q/%d", str, num)
				return
			}
		}
	}()
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
}
