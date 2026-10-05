package trap

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/guoyyit/snmp-agent-go/oid"
	"github.com/guoyyit/snmp-agent-go/snmp"
)

// fakeManager is a loopback UDP peer that records received packets and
// optionally acknowledges informs.
type fakeManager struct {
	conn     *net.UDPConn
	mu       sync.Mutex
	received int
	ack      bool
	closed   chan struct{}
}

func startFakeManager(t *testing.T, ack bool) *fakeManager {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	m := &fakeManager{conn: conn, ack: ack, closed: make(chan struct{})}
	go m.serve()
	return m
}

func (m *fakeManager) serve() {
	buf := make([]byte, 2048)
	for {
		n, src, err := m.conn.ReadFromUDP(buf)
		if err != nil {
			close(m.closed)
			return
		}
		m.mu.Lock()
		m.received++
		shouldAck := m.ack
		m.mu.Unlock()
		if shouldAck {
			msg, err := snmp.DecodeMessage(buf[:n])
			if err == nil && msg.PDU.Type == snmp.InformRequest {
				resp := &snmp.Message{
					Version: snmp.Version2c, Community: msg.Community,
					PDU: &snmp.PDU{Type: snmp.ResponsePDU, RequestID: msg.PDU.RequestID, VarBinds: msg.PDU.VarBinds},
				}
				data, _ := snmp.EncodeMessage(resp)
				_, _ = m.conn.WriteToUDP(data, src)
			}
		}
	}
}

func (m *fakeManager) addr() string { return m.conn.LocalAddr().String() }

func (m *fakeManager) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.received
}

func (m *fakeManager) close() { m.conn.Close(); <-m.closed }

func informPDU(id int32) *snmp.PDU {
	o, _ := oid.Parse("1.3.6.1.2.1.1.3.0")
	return &snmp.PDU{Type: snmp.InformRequest, RequestID: id,
		VarBinds: []snmp.VarBind{{Name: o, Value: snmp.TimeTicks(1)}}}
}

func TestSendTrap(t *testing.T) {
	mgr := startFakeManager(t, false)
	defer mgr.close()
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.SetManager(mgr.addr()); err != nil {
		t.Fatal(err)
	}
	o, _ := oid.Parse("1.3.6.1.6.3.1.1.4.1.0")
	if err := s.SendTrap("public", &snmp.PDU{
		RequestID: 1,
		VarBinds:  []snmp.VarBind{{Name: o, Value: snmp.Null{}}},
	}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if mgr.count() != 1 {
		t.Fatalf("manager received %d traps", mgr.count())
	}
}

func TestInformAcked(t *testing.T) {
	mgr := startFakeManager(t, true)
	defer mgr.close()
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_ = s.SetManager(mgr.addr())
	s.SetRetryPolicy(100*time.Millisecond, 3)

	done := make(chan error, 1)
	go func() { done <- s.SendInform("public", informPDU(100)) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("inform failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("inform was not acknowledged in time")
	}
	if mgr.count() != 1 {
		t.Fatalf("expected exactly one inform, got %d", mgr.count())
	}
}

func TestInformTimeout(t *testing.T) {
	mgr := startFakeManager(t, false) // never acks
	defer mgr.close()
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_ = s.SetManager(mgr.addr())
	s.SetRetryPolicy(20*time.Millisecond, 3)

	start := time.Now()
	err = s.SendInform("public", informPDU(101))
	if !errors.Is(err, ErrNoAck) {
		t.Fatalf("want ErrNoAck, got %v", err)
	}
	if time.Since(start) < 40*time.Millisecond {
		t.Fatal("returned before retransmissions completed")
	}
	if got := mgr.count(); got != 3 {
		t.Fatalf("want 3 attempts, got %d", got)
	}
}

func TestRetransmitTargetsLatestManager(t *testing.T) {
	old := startFakeManager(t, false) // drops everything
	defer old.close()
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_ = s.SetManager(old.addr())
	s.SetRetryPolicy(50*time.Millisecond, 5)

	// After the first attempt times out, repoint at an acknowledging manager.
	go func() {
		time.Sleep(70 * time.Millisecond)
		fresh := startFakeManager(t, true)
		_ = s.SetManager(fresh.addr())
	}()

	if err := s.SendInform("public", informPDU(200)); err != nil {
		t.Fatalf("inform failed after repoint: %v", err)
	}
	if old.count() < 1 {
		t.Fatal("old manager never received the initial attempt")
	}
}

func TestDuplicateAckDoesNotCrossWires(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Stand up two sockets on the sender's destination and send two ack
	// datagrams with the same id; the inform must return once and a later
	// inform with a different id must not mistake the stale acks.
	mgrConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer mgrConn.Close()
	_ = s.SetManager(mgrConn.LocalAddr().String())
	s.SetRetryPolicy(200*time.Millisecond, 2)

	senderAddr := s.conn.LocalAddr().(*net.UDPAddr)
	sendAck := func(id int32) {
		resp := &snmp.Message{Version: snmp.Version2c, Community: "public",
			PDU: &snmp.PDU{Type: snmp.ResponsePDU, RequestID: id}}
		data, _ := snmp.EncodeMessage(resp)
		_, _ = mgrConn.WriteToUDP(data, senderAddr)
	}

	done := make(chan error, 1)
	go func() { done <- s.SendInform("public", informPDID(300)) }()
	time.Sleep(50 * time.Millisecond)
	sendAck(300)
	sendAck(300) // duplicate ack
	if err := <-done; err != nil {
		t.Fatalf("inform failed: %v", err)
	}

	// A subsequent inform with a new id must wait for its own ack; the stale
	// duplicate ack for id 300 cannot satisfy it.
	done2 := make(chan error, 1)
	go func() { done2 <- s.SendInform("public", informPDID(301)) }()
	time.Sleep(50 * time.Millisecond)
	select {
	case err := <-done2:
		if !errors.Is(err, ErrNoAck) {
			t.Fatalf("stale ack satisfied a different inform: %v", err)
		}
	case <-time.After(600 * time.Millisecond):
		t.Fatal("second inform hung")
	}
}

// informPDID builds an inform PDU with a given request id.
func informPDID(id int32) *snmp.PDU { return informPDU(id) }
