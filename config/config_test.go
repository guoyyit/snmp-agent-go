package config

import (
	"path/filepath"
	"testing"
)

func TestDefaultWhenMissing(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ReadOnlyCommunity != "public" || cfg.ReadWriteCommunity != "private" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestSaveLoadRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfg.json")
	cfg := Default()
	cfg.Values["1.3.6.1.1.0"] = NewPersistedValue("OctetString", []byte("host"))
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	v := got.Values["1.3.6.1.1.0"]
	if v.Syntax != "OctetString" {
		t.Fatalf("syntax = %q", v.Syntax)
	}
	raw, err := v.DecodeRaw()
	if err != nil || string(raw) != "host" {
		t.Fatalf("raw = %q, %v", raw, err)
	}
}

func TestRejectsEqualCommunities(t *testing.T) {
	cfg := Default()
	cfg.ReadWriteCommunity = "public"
	if err := cfg.Validate(); err == nil {
		t.Fatal("equal communities accepted")
	}
}
