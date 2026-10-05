package main

import (
	"sort"
	"sync"
)

// mibObject is a single managed node.
type mibObject struct {
	oid      []int
	tag      byte
	writable bool
	maxLen   int // max OCTET STRING length; 0 means unlimited
	intVal   int64
	strVal   []byte
	oidVal   []int
	uintVal  uint32
}

// toVarbind copies the object's current value into a varbind.
func (o *mibObject) toVarbind() varbind {
	vb := varbind{oid: append([]int(nil), o.oid...), tag: o.tag}
	switch o.tag {
	case tagInteger:
		vb.value = o.intVal
	case tagOctetString:
		vb.value = append([]byte(nil), o.strVal...)
	case tagOID:
		vb.value = append([]int(nil), o.oidVal...)
	case tagCounter32, tagGauge32, tagTimeTicks:
		vb.value = o.uintVal
	}
	return vb
}

// assign stores a varbind value into the object. Caller must have
// validated type and length already.
func (o *mibObject) assign(vb varbind) {
	switch o.tag {
	case tagInteger:
		o.intVal, _ = vb.value.(int64)
	case tagOctetString:
		s, _ := vb.value.([]byte)
		o.strVal = append(o.strVal[:0], s...)
	case tagOID:
		oid, _ := vb.value.([]int)
		o.oidVal = append(o.oidVal[:0], oid...)
	case tagCounter32, tagGauge32, tagTimeTicks:
		o.uintVal, _ = vb.value.(uint32)
	}
}

// mibStore holds objects sorted lexicographically by OID.
type mibStore struct {
	mu      sync.RWMutex
	objects []*mibObject
}

func oidCompare(a, b []int) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

func newMIBStore() *mibStore {
	return &mibStore{}
}

// add registers an object, keeping the store sorted.
func (s *mibStore) add(obj *mibObject) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := sort.Search(len(s.objects), func(i int) bool {
		return oidCompare(s.objects[i].oid, obj.oid) >= 0
	})
	s.objects = append(s.objects, nil)
	copy(s.objects[i+1:], s.objects[i:])
	s.objects[i] = obj
}

// get returns the object with the exact OID, or nil.
func (s *mibStore) get(oid []int) *mibObject {
	s.mu.RLock()
	defer s.mu.RUnlock()
	i := sort.Search(len(s.objects), func(i int) bool {
		return oidCompare(s.objects[i].oid, oid) >= 0
	})
	if i < len(s.objects) && oidCompare(s.objects[i].oid, oid) == 0 {
		return s.objects[i]
	}
	return nil
}

// getNext returns the first object whose OID is strictly greater than oid.
func (s *mibStore) getNext(oid []int) *mibObject {
	s.mu.RLock()
	defer s.mu.RUnlock()
	i := sort.Search(len(s.objects), func(i int) bool {
		return oidCompare(s.objects[i].oid, oid) > 0
	})
	if i < len(s.objects) {
		return s.objects[i]
	}
	return nil
}

// getVarbind returns a copy of the object at oid as a varbind.
func (s *mibStore) getVarbind(oid []int) (varbind, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	i := sort.Search(len(s.objects), func(j int) bool {
		return oidCompare(s.objects[j].oid, oid) >= 0
	})
	if i < len(s.objects) && oidCompare(s.objects[i].oid, oid) == 0 {
		return s.objects[i].toVarbind(), true
	}
	return varbind{}, false
}

// getMany resolves many OIDs under a single read lock, so callers observe
// one consistent snapshot even while a Set is being applied. Missing
// objects yield a noSuchObject exception varbind.
func (s *mibStore) getMany(oids [][]int) []varbind {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]varbind, 0, len(oids))
	for _, oid := range oids {
		i := sort.Search(len(s.objects), func(j int) bool {
			return oidCompare(s.objects[j].oid, oid) >= 0
		})
		if i < len(s.objects) && oidCompare(s.objects[i].oid, oid) == 0 {
			out = append(out, s.objects[i].toVarbind())
		} else {
			out = append(out, varbind{oid: oid, tag: tagNoSuchObject})
		}
	}
	return out
}

// nextMany resolves the lexicographic successor of each OID under a
// single read lock. OIDs past the last object yield endOfMibView.
func (s *mibStore) nextMany(oids [][]int) []varbind {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]varbind, 0, len(oids))
	for _, oid := range oids {
		out = append(out, s.nextLocked(oid))
	}
	return out
}

// nextLocked finds the successor of oid; caller must hold the lock.
func (s *mibStore) nextLocked(oid []int) varbind {
	i := sort.Search(len(s.objects), func(j int) bool {
		return oidCompare(s.objects[j].oid, oid) > 0
	})
	if i < len(s.objects) {
		return s.objects[i].toVarbind()
	}
	return varbind{oid: oid, tag: tagEndOfMibView}
}

// bulkWalk computes a GetBulk response under a single read lock:
// nonRepeaters leading OIDs advance once, the rest repeat up to
// maxRepetitions times.
func (s *mibStore) bulkWalk(nonRepeaters, maxRepetitions int, oids [][]int) []varbind {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []varbind
	for i := 0; i < nonRepeaters && i < len(oids); i++ {
		out = append(out, s.nextLocked(oids[i]))
	}
	if maxRepetitions > 0 {
		for i := nonRepeaters; i < len(oids); i++ {
			cur := oids[i]
			for r := 0; r < maxRepetitions; r++ {
				vb := s.nextLocked(cur)
				out = append(out, vb)
				if vb.tag == tagEndOfMibView {
					break
				}
				cur = vb.oid
			}
		}
	}
	return out
}

// nextVarbind returns a copy of the first object after oid as a varbind.
func (s *mibStore) nextVarbind(oid []int) (varbind, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	i := sort.Search(len(s.objects), func(j int) bool {
		return oidCompare(s.objects[j].oid, oid) > 0
	})
	if i < len(s.objects) {
		return s.objects[i].toVarbind(), true
	}
	return varbind{}, false
}

// validateSet checks a single varbind against the target object.
func validateSet(o *mibObject, vb varbind) int {
	if o == nil {
		return errNoSuchName
	}
	if !o.writable {
		return errNotWritable
	}
	if vb.tag != o.tag {
		return errWrongType
	}
	switch o.tag {
	case tagOctetString:
		s, _ := vb.value.([]byte)
		if o.maxLen > 0 && len(s) > o.maxLen {
			return errWrongLength
		}
	case tagCounter32, tagGauge32, tagTimeTicks:
		if _, ok := vb.value.(uint32); !ok {
			return errWrongType
		}
	case tagInteger:
		if _, ok := vb.value.(int64); !ok {
			return errWrongType
		}
	}
	return errNoError
}

// set applies all varbinds atomically. On success returns errNoError.
// On failure no object is modified and the error status plus 1-based
// varbind index are returned.
func (s *mibStore) set(vbs []varbind) (errStatus, errIndex int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Phase 1: validate every varbind; nothing is modified on failure.
	targets := make([]*mibObject, len(vbs))
	for i, vb := range vbs {
		var o *mibObject
		idx := sort.Search(len(s.objects), func(j int) bool {
			return oidCompare(s.objects[j].oid, vb.oid) >= 0
		})
		if idx < len(s.objects) && oidCompare(s.objects[idx].oid, vb.oid) == 0 {
			o = s.objects[idx]
		}
		if st := validateSet(o, vb); st != errNoError {
			return st, i + 1
		}
		targets[i] = o
	}
	// Phase 2: apply all changes while the write lock is held, so
	// concurrent readers only ever see the full old or new state.
	for i, vb := range vbs {
		targets[i].assign(vb)
	}
	return errNoError, 0
}

// increment adds delta to a Counter32 or Gauge32 object. Counter32 wraps
// to zero past its maximum; Gauge32 clamps at its maximum.
func (s *mibStore) increment(oid []int, delta uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := sort.Search(len(s.objects), func(j int) bool {
		return oidCompare(s.objects[j].oid, oid) >= 0
	})
	if i >= len(s.objects) || oidCompare(s.objects[i].oid, oid) != 0 {
		return
	}
	o := s.objects[i]
	switch o.tag {
	case tagCounter32, tagTimeTicks:
		o.uintVal += delta // uint32 arithmetic wraps naturally
	case tagGauge32:
		if o.uintVal+delta < o.uintVal {
			o.uintVal = 0xffffffff
		} else {
			o.uintVal += delta
		}
	}
}

// restoreWritable applies a persisted value to a writable object,
// silently skipping unknown or mismatched entries.
func (s *mibStore) restoreWritable(vb varbind) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := sort.Search(len(s.objects), func(j int) bool {
		return oidCompare(s.objects[j].oid, vb.oid) >= 0
	})
	if i >= len(s.objects) || oidCompare(s.objects[i].oid, vb.oid) != 0 {
		return
	}
	o := s.objects[i]
	if !o.writable || o.tag != vb.tag {
		return
	}
	o.assign(vb)
}

// snapshotWritable returns a consistent copy of all writable objects.
func (s *mibStore) snapshotWritable() []varbind {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []varbind
	for _, o := range s.objects {
		if o.writable {
			out = append(out, o.toVarbind())
		}
	}
	return out
}
