package main

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// startTestAgent launches an agent on an ephemeral loopback port.
func startTestAgent(t *testing.T, cfg *config, mib *mibStore) (*agent, string) {
	t.Helper()
	if cfg == nil {
		cfg = defaultConfig()
	}
	cfg.ListenAddr = "127.0.0.1:0"
	if cfg.StatePath == "" || cfg.StatePath == defaultConfig().StatePath {
		cfg.StatePath = filepath.Join(t.TempDir(), "state.json")
	}
	a := newAgent(cfg, mib)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		a.shutdown()
	})
	go a.serve(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for a.conn.Load() == nil {
		if time.Now().After(deadline) {
			t.Fatal("agent did not bind in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return a, a.conn.Load().LocalAddr().String()
}

// rpc sends one request and waits for the response PDU.
func rpc(t *testing.T, addr, community string, p *pdu) *pdu {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(encodeMessage(community, p)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_, resp, err := decodeMessage(buf[:n])
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

// rpcRaw sends raw bytes and returns raw response bytes (may time out).
func rpcRaw(t *testing.T, addr string, data []byte, wait time.Duration) []byte {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(wait))
	if _, err := conn.Write(data); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

func oidOf(s *mibStore, i int) []int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]int(nil), s.objects[i].oid...)
}

func TestGetAndGetNextOverUDP(t *testing.T) {
	mib := testStore()
	_, addr := startTestAgent(t, nil, mib)
	first := oidOf(mib, 0)

	// Get existing object.
	resp := rpc(t, addr, "public", &pdu{tag: pduGetRequest, requestID: 1,
		varbinds: []varbind{{oid: first, tag: tagNull}}})
	if resp.errorStatus != 0 || len(resp.varbinds) != 1 {
		t.Fatalf("get: status=%d vbs=%d", resp.errorStatus, len(resp.varbinds))
	}
	if string(resp.varbinds[0].value.([]byte)) != "descr" {
		t.Fatalf("get value: %v", resp.varbinds[0].value)
	}

	// Get nonexistent object: noSuchObject exception.
	resp = rpc(t, addr, "public", &pdu{tag: pduGetRequest, requestID: 2,
		varbinds: []varbind{{oid: []int{1, 2, 3, 4}, tag: tagNull}}})
	if resp.varbinds[0].tag != tagNoSuchObject {
		t.Fatalf("nonexistent get: tag=%#x", resp.varbinds[0].tag)
	}

	// GetNext from before the first object returns the first object.
	resp = rpc(t, addr, "public", &pdu{tag: pduGetNextRequest, requestID: 3,
		varbinds: []varbind{{oid: []int{0, 0}, tag: tagNull}}})
	if oidCompare(resp.varbinds[0].oid, first) != 0 {
		t.Fatalf("getnext first: %v", resp.varbinds[0].oid)
	}

	// GetNext past the last object: endOfMibView.
	resp = rpc(t, addr, "public", &pdu{tag: pduGetNextRequest, requestID: 4,
		varbinds: []varbind{{oid: []int{9, 9, 9}, tag: tagNull}}})
	if resp.varbinds[0].tag != tagEndOfMibView {
		t.Fatalf("getnext end: tag=%#x", resp.varbinds[0].tag)
	}
}

func TestGetBulkSemantics(t *testing.T) {
	mib := testStore()
	_, addr := startTestAgent(t, nil, mib)
	base := []int{0}

	// nonRepeaters=1, maxRepetitions=2 over two varbinds.
	resp := rpc(t, addr, "public", &pdu{
		tag: pduGetBulkRequest, requestID: 10,
		errorStatus: 1, errorIndex: 2,
		varbinds: []varbind{
			{oid: base, tag: tagNull},
			{oid: base, tag: tagNull},
		}})
	// Expect: 1 non-repeater result + 2 repeater results.
	if len(resp.varbinds) != 3 {
		t.Fatalf("bulk count: got %d, want 3", len(resp.varbinds))
	}
	for i, vb := range resp.varbinds {
		if vb.tag == tagEndOfMibView {
			t.Fatalf("bulk vb %d unexpectedly endOfMibView", i)
		}
	}
	// The repeater column must advance lexicographically.
	if oidCompare(resp.varbinds[1].oid, resp.varbinds[2].oid) >= 0 {
		t.Fatalf("bulk repetition not advancing: %v then %v",
			resp.varbinds[1].oid, resp.varbinds[2].oid)
	}

	// maxRepetitions larger than the table: ends with endOfMibView,
	// deterministically.
	resp = rpc(t, addr, "public", &pdu{
		tag: pduGetBulkRequest, requestID: 11,
		errorStatus: 0, errorIndex: 100,
		varbinds: []varbind{{oid: base, tag: tagNull}}})
	last := resp.varbinds[len(resp.varbinds)-1]
	if last.tag != tagEndOfMibView {
		t.Fatalf("bulk walk-off: last tag=%#x", last.tag)
	}
	if len(resp.varbinds) != len(mib.objects)+1 {
		t.Fatalf("bulk walk-off count: %d", len(resp.varbinds))
	}
}

func TestGetBulkEmptyMIB(t *testing.T) {
	_, addr := startTestAgent(t, nil, newMIBStore())
	resp := rpc(t, addr, "public", &pdu{
		tag: pduGetBulkRequest, requestID: 12,
		errorStatus: 0, errorIndex: 5,
		varbinds: []varbind{{oid: []int{1, 3}, tag: tagNull}}})
	if len(resp.varbinds) != 1 || resp.varbinds[0].tag != tagEndOfMibView {
		t.Fatalf("empty mib bulk: %+v", resp.varbinds)
	}
}

func TestGetBulkResponseSizeLimit(t *testing.T) {
	mib := newMIBStore()
	for i := 0; i < 200; i++ {
		mib.add(&mibObject{
			oid:    []int{1, 3, 6, 1, 4, 1, 1, i + 1, 0},
			tag:    tagOctetString,
			strVal: []byte("some reasonably long value string"),
		})
	}
	cfg := defaultConfig()
	cfg.ResponseSizeLimit = 512
	_, addr := startTestAgent(t, cfg, mib)

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	req := encodeMessage("public", &pdu{
		tag: pduGetBulkRequest, requestID: 13,
		errorStatus: 0, errorIndex: 200,
		varbinds: []varbind{{oid: []int{0, 0}, tag: tagNull}}})
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n > cfg.ResponseSizeLimit {
		t.Fatalf("response %d bytes exceeds limit %d", n, cfg.ResponseSizeLimit)
	}
	_, resp, err := decodeMessage(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.varbinds) == 0 || len(resp.varbinds) >= 200 {
		t.Fatalf("expected trimmed varbind list, got %d", len(resp.varbinds))
	}
}

func TestSetAccessControl(t *testing.T) {
	mib := testStore()
	_, addr := startTestAgent(t, nil, mib)
	nameOID := []int{1, 3, 6, 1, 2, 1, 1, 5, 0}
	setReq := &pdu{tag: pduSetRequest, requestID: 20,
		varbinds: []varbind{{oid: nameOID, tag: tagOctetString,
			value: []byte("rw")}}}

	// Wrong community: no response at all.
	if out := rpcRaw(t, addr, encodeMessage("evil", setReq),
		300*time.Millisecond); out != nil {
		t.Fatalf("wrong community got response: %x", out)
	}
	// Read-only community: no response at all.
	if out := rpcRaw(t, addr, encodeMessage("public", setReq),
		300*time.Millisecond); out != nil {
		t.Fatalf("ro community got set response: %x", out)
	}
	// Value must be unchanged.
	vb, _ := mib.getVarbind(nameOID)
	if string(vb.value.([]byte)) != "name" {
		t.Fatalf("unauthorized set leaked: %q", vb.value)
	}
	// Read-write community: success.
	resp := rpc(t, addr, "private", setReq)
	if resp.errorStatus != 0 {
		t.Fatalf("rw set: status=%d index=%d", resp.errorStatus, resp.errorIndex)
	}
	vb, _ = mib.getVarbind(nameOID)
	if string(vb.value.([]byte)) != "rw" {
		t.Fatalf("rw set not applied: %q", vb.value)
	}
	// Read-only community can still read.
	resp = rpc(t, addr, "public", &pdu{tag: pduGetRequest, requestID: 21,
		varbinds: []varbind{{oid: nameOID, tag: tagNull}}})
	if string(resp.varbinds[0].value.([]byte)) != "rw" {
		t.Fatalf("ro get after set: %q", resp.varbinds[0].value)
	}
}

func TestSetAtomicOverUDP(t *testing.T) {
	mib := testStore()
	_, addr := startTestAgent(t, nil, mib)
	okOID := []int{1, 3, 6, 1, 2, 1, 1, 5, 0}
	roOID := []int{1, 3, 6, 1, 2, 1, 1, 1, 0}
	resp := rpc(t, addr, "private", &pdu{tag: pduSetRequest, requestID: 30,
		varbinds: []varbind{
			{oid: okOID, tag: tagOctetString, value: []byte("changed")},
			{oid: roOID, tag: tagOctetString, value: []byte("nope")},
		}})
	if resp.errorStatus != errNotWritable || resp.errorIndex != 2 {
		t.Fatalf("status=%d index=%d", resp.errorStatus, resp.errorIndex)
	}
	vb, _ := mib.getVarbind(okOID)
	if string(vb.value.([]byte)) != "name" {
		t.Fatalf("atomic set leaked: %q", vb.value)
	}
}

func TestMalformedPacketsDropped(t *testing.T) {
	mib := testStore()
	_, addr := startTestAgent(t, nil, mib)
	junk := [][]byte{
		{},
		{0x00},
		{0x30, 0x03, 0x02, 0x01},                 // truncated
		{0x30, 0x80},                             // indefinite length
		encodeMessage("public", &pdu{tag: 0xA4}), // v1 GetBulk: unknown tag
	}
	for i, pkt := range junk {
		if out := rpcRaw(t, addr, pkt, 200*time.Millisecond); out != nil {
			t.Fatalf("junk packet %d got response: %x", i, out)
		}
	}
	// Agent must still serve valid requests afterwards.
	resp := rpc(t, addr, "public", &pdu{tag: pduGetNextRequest, requestID: 40,
		varbinds: []varbind{{oid: []int{0, 0}, tag: tagNull}}})
	if len(resp.varbinds) != 1 {
		t.Fatal("agent unresponsive after junk packets")
	}
}
