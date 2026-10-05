package main

import (
	"context"
	"errors"
	"log"
	"net"
	"sync/atomic"
	"time"
)

// agent is the SNMP agent server.
type agent struct {
	cfg  *config
	mib  *mibStore
	conn atomic.Pointer[net.UDPConn]
	trap *trapSender
}

func newAgent(cfg *config, mib *mibStore) *agent {
	return &agent{cfg: cfg, mib: mib, trap: newTrapSender(cfg)}
}

// serve binds the UDP socket and serves requests until ctx is cancelled.
func (a *agent) serve(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", a.cfg.ListenAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	a.conn.Store(conn)
	a.trap.setConn(conn)
	defer conn.Close()
	go func() {
		<-ctx.Done()
		conn.Close()
	}()
	log.Printf("snmp-agent-go: listening on %s", conn.LocalAddr())
	buf := make([]byte, 65535)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		pkt := append([]byte(nil), buf[:n]...)
		if resp := a.handlePacket(pkt, src); resp != nil {
			if _, err := conn.WriteToUDP(resp, src); err != nil {
				log.Printf("write response to %s: %v", src, err)
			}
		}
	}
}

// handlePacket processes one request datagram; returns the response bytes
// or nil if the packet must be silently dropped.
func (a *agent) handlePacket(data []byte, src *net.UDPAddr) []byte {
	community, p, err := decodeMessage(data)
	if err != nil {
		return nil // silently drop malformed packets
	}
	level := a.cfg.accessLevelFor(community)
	if level == accessNone {
		return nil // unauthorized community: no response at all
	}
	a.trap.setManagerAddr(src)
	var resp *pdu
	switch p.tag {
	case pduGetRequest:
		resp = a.handleGet(p)
	case pduGetNextRequest:
		resp = a.handleGetNext(p)
	case pduGetBulkRequest:
		resp = a.handleGetBulk(p)
	case pduSetRequest:
		if level != accessReadWrite {
			return nil // read-only community must not set; drop silently
		}
		resp = a.handleSet(p)
	case pduResponse:
		a.trap.handleResponse(p, src)
		return nil
	default:
		return nil
	}
	out := encodeMessage(community, resp)
	if len(out) > a.cfg.ResponseSizeLimit && p.tag != pduGetBulkRequest {
		// Response does not fit: report tooBig with an empty varbind list.
		big := &pdu{tag: pduResponse, requestID: p.requestID,
			errorStatus: errTooBig, errorIndex: 0}
		out = encodeMessage(community, big)
	}
	return out
}

// handleGet answers a GetRequest. Missing objects yield a noSuchObject
// exception in the corresponding varbind (RFC 1905 section 4.2.1).
func (a *agent) handleGet(p *pdu) *pdu {
	return &pdu{tag: pduResponse, requestID: p.requestID,
		varbinds: a.mib.getMany(vbOIDs(p.varbinds))}
}

// handleGetNext answers a GetNextRequest. Walking past the last object
// yields endOfMibView (RFC 1905 section 4.2.2).
func (a *agent) handleGetNext(p *pdu) *pdu {
	return &pdu{tag: pduResponse, requestID: p.requestID,
		varbinds: a.mib.nextMany(vbOIDs(p.varbinds))}
}

// handleGetBulk answers a GetBulkRequest (RFC 1905 section 4.2.3). The
// first nonRepeaters varbinds advance once; the rest repeat up to
// maxRepetitions times. The result is trimmed to fit the response size
// limit; an empty MIB deterministically yields endOfMibView varbinds.
func (a *agent) handleGetBulk(p *pdu) *pdu {
	nonRepeaters := int(p.errorStatus)
	if nonRepeaters < 0 {
		nonRepeaters = 0
	}
	maxRepetitions := int(p.errorIndex)
	if maxRepetitions < 0 {
		maxRepetitions = 0
	}
	out := a.mib.bulkWalk(nonRepeaters, maxRepetitions, vbOIDs(p.varbinds))
	resp := &pdu{tag: pduResponse, requestID: p.requestID, varbinds: out}
	// Trim trailing varbinds until the encoded response fits the limit.
	for len(resp.varbinds) > 0 {
		if len(encodeMessage("", resp)) <= a.cfg.ResponseSizeLimit {
			break
		}
		resp.varbinds = resp.varbinds[:len(resp.varbinds)-1]
	}
	if len(out) > 0 && len(resp.varbinds) == 0 {
		// Nothing fits: report tooBig with an empty varbind list.
		resp.errorStatus = errTooBig
	}
	return resp
}

// vbOIDs extracts the OID of each varbind.
func vbOIDs(vbs []varbind) [][]int {
	out := make([][]int, len(vbs))
	for i, vb := range vbs {
		out[i] = vb.oid
	}
	return out
}

// handleSet applies a SetRequest atomically and persists the new state.
func (a *agent) handleSet(p *pdu) *pdu {
	status, index := a.mib.set(p.varbinds)
	resp := &pdu{
		tag:         pduResponse,
		requestID:   p.requestID,
		errorStatus: int32(status),
		errorIndex:  int32(index),
	}
	if status == errNoError {
		resp.varbinds = p.varbinds
		if err := saveState(a.cfg.StatePath, a.mib); err != nil {
			log.Printf("persist state: %v", err)
		}
	}
	return resp
}

// shutdown persists state and stops retransmissions.
func (a *agent) shutdown() {
	a.trap.close()
	if err := saveState(a.cfg.StatePath, a.mib); err != nil {
		log.Printf("persist state on shutdown: %v", err)
	}
}

// tickCounters demonstrates Counter32/Gauge32 semantics in the background.
func (a *agent) tickCounters(ctx context.Context, oid []int, delta uint32, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.mib.increment(oid, delta)
		}
	}
}
