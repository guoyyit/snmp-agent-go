package main

import (
	"log"
	"net"
	"sync"
	"time"
)

// trapSender sends Trap and InformRequest notifications with
// retransmission and acknowledgement tracking.
type trapSender struct {
	cfg  *config
	conn *net.UDPConn

	mu      sync.Mutex
	manager *net.UDPAddr // latest known manager address
	pending map[int32]*informState
	nextID  int32
	closed  bool
}

// informState tracks one unacknowledged InformRequest.
type informState struct {
	msg  []byte
	done chan struct{}
}

func newTrapSender(cfg *config) *trapSender {
	return &trapSender{cfg: cfg, pending: make(map[int32]*informState)}
}

// setConn provides the UDP socket used to send notifications.
func (t *trapSender) setConn(conn *net.UDPConn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.conn = conn
}

// setManagerAddr records the most recent manager address; inform
// retransmissions always target the latest known address.
func (t *trapSender) setManagerAddr(addr *net.UDPAddr) {
	if addr == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	cp := *addr
	t.manager = &cp
}

// informTarget resolves where informs are sent right now: the latest
// manager address if known, otherwise the first configured trap target.
func (t *trapSender) informTarget() *net.UDPAddr {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.manager != nil {
		cp := *t.manager
		return &cp
	}
	if len(t.cfg.TrapTargets) > 0 {
		if addr, err := net.ResolveUDPAddr("udp", t.cfg.TrapTargets[0]); err == nil {
			return addr
		}
	}
	return nil
}

// trapTargets resolves all destinations for unsolicited traps.
func (t *trapSender) trapTargets() []*net.UDPAddr {
	t.mu.Lock()
	manager := t.manager
	t.mu.Unlock()
	var out []*net.UDPAddr
	for _, s := range t.cfg.TrapTargets {
		if addr, err := net.ResolveUDPAddr("udp", s); err == nil {
			out = append(out, addr)
		}
	}
	if len(out) == 0 && manager != nil {
		cp := *manager
		out = append(out, &cp)
	}
	return out
}

// writeTo sends raw bytes to addr over the agent socket.
func (t *trapSender) writeTo(msg []byte, addr *net.UDPAddr) error {
	t.mu.Lock()
	conn := t.conn
	t.mu.Unlock()
	if conn == nil || addr == nil {
		return nil
	}
	_, err := conn.WriteToUDP(msg, addr)
	return err
}

// sendTrap fires an unacknowledged SNMPv2-Trap to all targets.
func (t *trapSender) sendTrap(vbs []varbind) error {
	p := &pdu{tag: pduTrapV2, requestID: t.allocID(), varbinds: vbs}
	msg := encodeMessage(t.cfg.TrapCommunity, p)
	for _, addr := range t.trapTargets() {
		if err := t.writeTo(msg, addr); err != nil {
			log.Printf("send trap to %s: %v", addr, err)
		}
	}
	return nil
}

// sendInform sends an InformRequest and retransmits until acknowledged
// or retries are exhausted.
func (t *trapSender) sendInform(vbs []varbind) error {
	id := t.allocID()
	p := &pdu{tag: pduInformRequest, requestID: id, varbinds: vbs}
	msg := encodeMessage(t.cfg.TrapCommunity, p)
	st := &informState{msg: msg, done: make(chan struct{})}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.pending[id] = st
	t.mu.Unlock()
	go t.retransmit(id, st)
	return nil
}

// retransmit sends the inform and retries on timeout, always aiming at
// the latest known manager address, until acknowledged or closed.
func (t *trapSender) retransmit(id int32, st *informState) {
	defer func() {
		t.mu.Lock()
		delete(t.pending, id)
		t.mu.Unlock()
	}()
	attempts := t.cfg.InformRetries + 1
	timeout := time.Duration(t.cfg.InformTimeoutMS) * time.Millisecond
	for i := 0; i < attempts; i++ {
		if err := t.writeTo(st.msg, t.informTarget()); err != nil {
			log.Printf("send inform %d: %v", id, err)
		}
		timer := time.NewTimer(timeout)
		select {
		case <-st.done:
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// handleResponse matches an incoming Response against pending informs;
// duplicate acknowledgements are ignored.
func (t *trapSender) handleResponse(p *pdu, src *net.UDPAddr) {
	t.mu.Lock()
	st, ok := t.pending[p.requestID]
	if ok {
		delete(t.pending, p.requestID)
	}
	t.mu.Unlock()
	if !ok {
		return // duplicate or unknown ack: ignore
	}
	select {
	case <-st.done: // already acknowledged
	default:
		close(st.done)
	}
}

// allocID returns a unique request id for outgoing notifications.
func (t *trapSender) allocID() int32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nextID++
	if t.nextID <= 0 {
		t.nextID = 1
	}
	return t.nextID
}

// close stops all retransmission timers.
func (t *trapSender) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.closed = true
	for id, st := range t.pending {
		delete(t.pending, id)
		select {
		case <-st.done:
		default:
			close(st.done)
		}
	}
}
