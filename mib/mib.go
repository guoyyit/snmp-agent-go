package mib

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/guoyyit/snmp-agent-go/ber"
	"github.com/guoyyit/snmp-agent-go/oid"
)

type Syntax uint8

const (
	SyntaxInteger32 Syntax = iota
	SyntaxOctetString
	SyntaxCounter32
	SyntaxGauge32
)

type Access uint8

const (
	AccessReadOnly Access = iota
	AccessReadWrite
)

var (
	ErrNotFound = errors.New("mib: object not found")
	ErrReadOnly = errors.New("mib: object is read-only")
	ErrBadType  = errors.New("mib: value type mismatch")
	ErrBadLen   = errors.New("mib: value length out of range")
	ErrBadValue = errors.New("mib: invalid value")
)

type Object struct {
	OID    oid.OID
	Name   string
	Syntax Syntax
	Access Access
	// MaxOctets bounds octet-string length; 0 means no limit.
	MaxOctets int
}

type SetItem struct {
	Name  oid.OID
	Value any
}

// SetError identifies the failing 1-based varbind index and the reason.
type SetError struct {
	Index int
	Err   error
}

func (e *SetError) Error() string { return fmt.Sprintf("mib: set failed at %d: %v", e.Index, e.Err) }
func (e *SetError) Unwrap() error { return e.Err }

// StoredValue is a persisted representation of a writable object value.
type StoredValue struct {
	Syntax Syntax
	Raw    []byte
}

// Value types are distinct named types even when they share an underlying
// representation, so Counter32 and Gauge32 values never silently mix.
type (
	Integer32   int32
	OctetString []byte
	Counter32   uint32
	Gauge32     uint32
)

type entry struct {
	def   Object
	value any
}

// MIB is the local management information base.
type MIB struct {
	mu      sync.RWMutex
	objects []*entry
}

func New() *MIB { return &MIB{} }

// Register adds a managed object. Duplicate OIDs are ignored.
func (m *MIB) Register(o Object, initial any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.objects {
		if e.def.OID.Equal(o.OID) {
			return
		}
	}
	if initial == nil {
		initial = zeroForSyntax(o.Syntax)
	}
	m.objects = append(m.objects, &entry{def: o, value: initial})
	sort.Slice(m.objects, func(i, j int) bool {
		return m.objects[i].def.OID.Compare(m.objects[j].def.OID) < 0
	})
}

func zeroForSyntax(s Syntax) any {
	switch s {
	case SyntaxInteger32:
		return Integer32(0)
	case SyntaxOctetString:
		return OctetString{}
	case SyntaxCounter32:
		return Counter32(0)
	case SyntaxGauge32:
		return Gauge32(0)
	}
	return nil
}

func (m *MIB) Get(name oid.OID) (value any, syn Syntax, acc Access, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	idx := m.indexOfLocked(name)
	if idx < 0 {
		return nil, 0, 0, false
	}
	e := m.objects[idx]
	return cloneValue(e.value), e.def.Syntax, e.def.Access, true
}

// GetNext returns the first object lexicographically greater than after.
func (m *MIB) GetNext(after oid.OID) (name oid.OID, value any, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	idx := sort.Search(len(m.objects), func(i int) bool {
		return m.objects[i].def.OID.Compare(after) > 0
	})
	if idx >= len(m.objects) {
		return nil, nil, false
	}
	e := m.objects[idx]
	return append(oid.OID(nil), e.def.OID...), cloneValue(e.value), true
}

func (m *MIB) indexOfLocked(name oid.OID) int {
	idx := sort.Search(len(m.objects), func(i int) bool {
		return m.objects[i].def.OID.Compare(name) >= 0
	})
	if idx < len(m.objects) && m.objects[idx].def.OID.Equal(name) {
		return idx
	}
	return -1
}

// ApplySet validates and applies all items atomically: either every varbind
// is committed, or no state changes at all.
func (m *MIB) ApplySet(items []SetItem) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	type pendingChange struct {
		idx   int
		value any
	}
	pending := make([]pendingChange, 0, len(items))
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		key := item.Name.String()
		order := len(pending)
		if seen[key] {
			return &SetError{Index: order + 1, Err: fmt.Errorf("%w: duplicate %s", ErrBadValue, item.Name)}
		}
		seen[key] = true
		idx := m.indexOfLocked(item.Name)
		if idx < 0 {
			return &SetError{Index: order + 1, Err: fmt.Errorf("%w: %s", ErrNotFound, item.Name)}
		}
		e := m.objects[idx]
		if e.def.Access != AccessReadWrite {
			return &SetError{Index: order + 1, Err: fmt.Errorf("%w: %s", ErrReadOnly, item.Name)}
		}
		v, err := coerceSetValue(e.def, item.Value)
		if err != nil {
			return &SetError{Index: order + 1, Err: err}
		}
		pending = append(pending, pendingChange{idx: idx, value: v})
	}
	for _, p := range pending {
		m.objects[p.idx].value = p.value
	}
	return nil
}

func coerceSetValue(def Object, v any) (any, error) {
	switch def.Syntax {
	case SyntaxInteger32:
		n, ok := v.(Integer32)
		if !ok {
			return nil, fmt.Errorf("%w: expect Integer32", ErrBadType)
		}
		return n, nil
	case SyntaxOctetString:
		s, ok := v.(OctetString)
		if !ok {
			return nil, fmt.Errorf("%w: expect OctetString", ErrBadType)
		}
		if def.MaxOctets > 0 && len(s) > def.MaxOctets {
			return nil, fmt.Errorf("%w: max %d", ErrBadLen, def.MaxOctets)
		}
		return OctetString(append([]byte(nil), s...)), nil
	case SyntaxCounter32:
		return nil, fmt.Errorf("%w: counters are not settable", ErrReadOnly)
	case SyntaxGauge32:
		g, ok := v.(Gauge32)
		if !ok {
			return nil, fmt.Errorf("%w: expect Gauge32", ErrBadType)
		}
		return g, nil
	default:
		return nil, ErrBadType
	}
}

// Increment adds delta to a Counter32 with wraparound at 2^32.
func (m *MIB) Increment(name oid.OID, delta uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	idx := m.indexOfLocked(name)
	if idx < 0 {
		return
	}
	e := m.objects[idx]
	if e.def.Syntax != SyntaxCounter32 {
		return
	}
	e.value = Counter32(uint32(e.value.(Counter32)) + delta)
}

// SetGauge assigns a Gauge32, clamping at the 32-bit maximum.
func (m *MIB) SetGauge(name oid.OID, v uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	idx := m.indexOfLocked(name)
	if idx < 0 || m.objects[idx].def.Syntax != SyntaxGauge32 {
		return
	}
	if v > 0xffffffff {
		v = 0xffffffff
	}
	m.objects[idx].value = Gauge32(v)
}

// WritableValues returns a point-in-time snapshot of read-write values.
func (m *MIB) WritableValues() map[string]StoredValue {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]StoredValue)
	for _, e := range m.objects {
		if e.def.Access != AccessReadWrite {
			continue
		}
		raw, err := encodeValue(e.value)
		if err != nil {
			continue
		}
		out[e.def.OID.String()] = StoredValue{Syntax: e.def.Syntax, Raw: raw}
	}
	return out
}

// RestoreValues replaces writable object values before serving requests.
func (m *MIB) RestoreValues(values map[string]StoredValue) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.objects {
		if e.def.Access != AccessReadWrite {
			continue
		}
		stored, ok := values[e.def.OID.String()]
		if !ok {
			continue
		}
		if v, err := decodeValue(e.def.Syntax, stored.Raw); err == nil {
			e.value = v
		}
	}
}

func cloneValue(v any) any {
	if s, ok := v.(OctetString); ok {
		return OctetString(append([]byte(nil), s...))
	}
	return v
}

// Snapshot returns a point-in-time copy of every object, ordered by OID.
// Readers use it to observe complete pre- or post-set states only.
func (m *MIB) Snapshot() []NamedValue {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]NamedValue, 0, len(m.objects))
	for _, e := range m.objects {
		out = append(out, NamedValue{
			Object: e.def,
			Value:  cloneValue(e.value),
		})
	}
	return out
}

// NamedValue pairs an object definition with its current value.
type NamedValue struct {
	Object Object
	Value  any
}

func encodeValue(v any) ([]byte, error) {
	switch x := v.(type) {
	case Integer32:
		return ber.Encode(ber.TagInteger, ber.EncodeInteger(int64(x))), nil
	case OctetString:
		return append([]byte(nil), x...), nil
	case Counter32:
		return ber.EncodeUnsigned(uint64(x)), nil
	case Gauge32:
		return ber.EncodeUnsigned(uint64(x)), nil
	default:
		return nil, ErrBadType
	}
}

func decodeValue(s Syntax, raw []byte) (any, error) {
	switch s {
	case SyntaxInteger32:
		v, err := ber.DecodeInteger(raw)
		if err != nil || v < -2147483648 || v > 2147483647 {
			return nil, ErrBadValue
		}
		return Integer32(v), nil
	case SyntaxOctetString:
		return OctetString(append([]byte(nil), raw...)), nil
	case SyntaxCounter32, SyntaxGauge32:
		v, err := ber.DecodeUnsigned(raw)
		if err != nil {
			return nil, ErrBadValue
		}
		if s == SyntaxCounter32 {
			return Counter32(v), nil
		}
		return Gauge32(v), nil
	default:
		return nil, ErrBadType
	}
}
