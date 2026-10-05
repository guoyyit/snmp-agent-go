package oid

import "testing"

func TestParseStringRoundtrip(t *testing.T) {
	cases := []string{"1.3.6.1.2.1", "0.0", "2.250.1"}
	for _, s := range cases {
		o, err := Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q): %v", s, err)
		}
		if o.String() != s {
			t.Fatalf("String() = %q, want %q", o.String(), s)
		}
	}
}

func TestParseInvalid(t *testing.T) {
	bad := []string{"", "1", "3.1", "1.40", "1.a.6", "1..6", "1.2.99999999999"}
	for _, s := range bad {
		if _, err := Parse(s); err == nil {
			t.Fatalf("Parse(%q) succeeded, want error", s)
		}
	}
}

func TestCompare(t *testing.T) {
	a := mustParse(t, "1.3.6.1")
	b := mustParse(t, "1.3.6.2")
	c := mustParse(t, "1.3.6.1.1")
	if a.Compare(b) != -1 || b.Compare(a) != 1 || a.Compare(a) != 0 {
		t.Fatal("sibling compare wrong")
	}
	if a.Compare(c) != -1 || c.Compare(a) != 1 {
		t.Fatal("prefix ordering wrong")
	}
	if !c.HasPrefix(a) || a.HasPrefix(c) {
		t.Fatal("HasPrefix wrong")
	}
}

func TestBERRoundtrip(t *testing.T) {
	o := mustParse(t, "1.3.6.1.2.1.1.1.0")
	enc, err := o.EncodeBER()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeBER(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !dec.Equal(o) {
		t.Fatalf("roundtrip = %v, want %v", dec, o)
	}
}

func TestBERFirstArc(t *testing.T) {
	for _, s := range []string{"0.0", "1.39", "2.99999"} {
		o := mustParse(t, s)
		enc, _ := o.EncodeBER()
		dec, err := DecodeBER(enc)
		if err != nil || !dec.Equal(o) {
			t.Fatalf("roundtrip %s: %v %v", s, dec, err)
		}
	}
}

func mustParse(t *testing.T, s string) OID {
	t.Helper()
	o, err := Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return o
}
