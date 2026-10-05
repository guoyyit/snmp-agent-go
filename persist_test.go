package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAndLoadState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s := testStore()
	nameOID := []int{1, 3, 6, 1, 2, 1, 1, 5, 0}
	gaugeOID := []int{1, 3, 6, 1, 4, 1, 1, 2, 0}
	if st, _ := s.set([]varbind{
		{oid: nameOID, tag: tagOctetString, value: []byte("persist")},
		{oid: gaugeOID, tag: tagGauge32, value: uint32(42)},
	}); st != errNoError {
		t.Fatal("setup set failed")
	}
	if err := saveState(path, s); err != nil {
		t.Fatal(err)
	}

	// Simulate a restart: fresh store with factory defaults.
	s2 := testStore()
	if err := loadState(path, s2); err != nil {
		t.Fatal(err)
	}
	vb, ok := s2.getVarbind(nameOID)
	if !ok || string(vb.value.([]byte)) != "persist" {
		t.Fatalf("name not restored: %v", vb.value)
	}
	vb, ok = s2.getVarbind(gaugeOID)
	if !ok || vb.value.(uint32) != 42 {
		t.Fatalf("gauge not restored: %v", vb.value)
	}
	// Read-only objects keep their defaults.
	vb, _ = s2.getVarbind([]int{1, 3, 6, 1, 2, 1, 1, 1, 0})
	if string(vb.value.([]byte)) != "descr" {
		t.Fatalf("read-only object clobbered: %q", vb.value)
	}
}

func TestLoadStateMissingAndCorrupt(t *testing.T) {
	dir := t.TempDir()
	// Missing file: defaults, no error.
	s := testStore()
	if err := loadState(filepath.Join(dir, "nope.json"), s); err != nil {
		t.Fatalf("missing file: %v", err)
	}
	// Corrupt file: error, store untouched.
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loadState(bad, s); err == nil {
		t.Fatal("expected error for corrupt state")
	}
	vb, _ := s.getVarbind([]int{1, 3, 6, 1, 2, 1, 1, 5, 0})
	if string(vb.value.([]byte)) != "name" {
		t.Fatal("corrupt load modified the store")
	}
	// Unknown OIDs in the state file are skipped.
	unknown := filepath.Join(dir, "unknown.json")
	data := `{"writable":[{"oid":"9.9.9.9.0","tag":4,"str":"aGk="}]}`
	if err := os.WriteFile(unknown, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loadState(unknown, s); err != nil {
		t.Fatalf("unknown oid: %v", err)
	}
}

func TestRestartRecoveryEndToEnd(t *testing.T) {
	cfg := defaultConfig()
	statePath := filepath.Join(t.TempDir(), "state.json")
	cfg.StatePath = statePath
	nameOID := []int{1, 3, 6, 1, 2, 1, 1, 5, 0}

	// First boot: set a writable object over UDP.
	mib1 := testStore()
	_, addr := startTestAgent(t, cfg, mib1)
	resp := rpc(t, addr, "private", &pdu{tag: pduSetRequest, requestID: 1,
		varbinds: []varbind{{oid: nameOID, tag: tagOctetString,
			value: []byte("restart!")}}})
	if resp.errorStatus != 0 {
		t.Fatalf("set: status=%d", resp.errorStatus)
	}
	// State file must exist after the set.
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("state not persisted: %v", err)
	}

	// Second boot: restore into a fresh store before serving.
	mib2 := testStore()
	if err := loadState(statePath, mib2); err != nil {
		t.Fatal(err)
	}
	_, addr2 := startTestAgent(t, cfg, mib2)
	resp = rpc(t, addr2, "public", &pdu{tag: pduGetRequest, requestID: 2,
		varbinds: []varbind{{oid: nameOID, tag: tagNull}}})
	if got := string(resp.varbinds[0].value.([]byte)); got != "restart!" {
		t.Fatalf("after restart: %q", got)
	}
}
