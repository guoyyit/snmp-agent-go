package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// persistedVarbind is the on-disk representation of one writable object.
type persistedVarbind struct {
	OID    string `json:"oid"`
	Tag    byte   `json:"tag"`
	Int    int64  `json:"int,omitempty"`
	Str    []byte `json:"str,omitempty"`
	OidVal []int  `json:"oidVal,omitempty"`
	U32    uint32 `json:"u32,omitempty"`
}

type persistedState struct {
	Writable []persistedVarbind `json:"writable"`
}

func oidToString(oid []int) string {
	parts := make([]string, len(oid))
	for i, n := range oid {
		parts[i] = fmt.Sprintf("%d", n)
	}
	return strings.Join(parts, ".")
}

func oidFromString(s string) ([]int, error) {
	var oid []int
	for _, p := range strings.Split(s, ".") {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err != nil || n < 0 {
			return nil, fmt.Errorf("invalid oid %q", s)
		}
		oid = append(oid, n)
	}
	if len(oid) < 2 {
		return nil, fmt.Errorf("invalid oid %q", s)
	}
	return oid, nil
}

func varbindToPersisted(vb varbind) persistedVarbind {
	pv := persistedVarbind{OID: oidToString(vb.oid), Tag: vb.tag}
	switch vb.tag {
	case tagInteger:
		pv.Int, _ = vb.value.(int64)
	case tagOctetString:
		pv.Str, _ = vb.value.([]byte)
	case tagOID:
		pv.OidVal, _ = vb.value.([]int)
	case tagCounter32, tagGauge32, tagTimeTicks:
		pv.U32, _ = vb.value.(uint32)
	}
	return pv
}

func persistedToVarbind(pv persistedVarbind) (varbind, error) {
	oid, err := oidFromString(pv.OID)
	if err != nil {
		return varbind{}, err
	}
	vb := varbind{oid: oid, tag: pv.Tag}
	switch pv.Tag {
	case tagInteger:
		vb.value = pv.Int
	case tagOctetString:
		vb.value = pv.Str
	case tagOID:
		vb.value = pv.OidVal
	case tagCounter32, tagGauge32, tagTimeTicks:
		vb.value = pv.U32
	default:
		return varbind{}, fmt.Errorf("unsupported tag %#x", pv.Tag)
	}
	return vb, nil
}

// saveState persists writable objects to path atomically.
func saveState(path string, s *mibStore) error {
	st := persistedState{}
	for _, vb := range s.snapshotWritable() {
		st.Writable = append(st.Writable, varbindToPersisted(vb))
	}
	data, err := json.MarshalIndent(&st, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// loadState restores writable objects from path into the store.
func loadState(path string, s *mibStore) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var st persistedState
	if err := json.Unmarshal(data, &st); err != nil {
		return err
	}
	for _, pv := range st.Writable {
		vb, err := persistedToVarbind(pv)
		if err != nil {
			return err
		}
		s.restoreWritable(vb)
	}
	return nil
}
