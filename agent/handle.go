package agent

import (
	"errors"
	"net"

	"github.com/guoyyit/snmp-agent-go/mib"
	"github.com/guoyyit/snmp-agent-go/snmp"
)

// MaxMessageSize bounds response datagrams, including the SNMP header.
const MaxMessageSize = 1472

type accessLevel int

const (
	accessNone accessLevel = iota
	accessReadOnly
	accessReadWrite
)

func (a *Agent) communityLevel(community string) accessLevel {
	switch community {
	case a.cfg.ReadWriteCommunity:
		return accessReadWrite
	case a.cfg.ReadOnlyCommunity:
		return accessReadOnly
	default:
		return accessNone
	}
}

// handle validates, dispatches and returns the raw response for one
// datagram. A nil result means the datagram must be dropped silently,
// including malformed packets and all unauthorized requests.
func (a *Agent) handle(data []byte, src *net.UDPAddr) []byte {
	msg, err := snmp.DecodeMessage(data)
	if err != nil || msg == nil || msg.PDU == nil {
		return nil
	}
	level := a.communityLevel(msg.Community)
	if level == accessNone {
		return nil
	}
	if src != nil {
		a.mu.RLock()
		observer := a.onPeer
		a.mu.RUnlock()
		if observer != nil {
			observer(src.String())
		}
	}

	var pdu *snmp.PDU
	switch msg.PDU.Type {
	case snmp.GetRequest:
		pdu = a.handleGet(msg.PDU)
	case snmp.GetNextRequest:
		pdu = a.handleGetNext(msg.PDU)
	case snmp.GetBulkRequest:
		pdu = bulkPDU(msg.PDU, a.mib, msg.Community, MaxMessageSize)
	case snmp.SetRequest:
		if level != accessReadWrite {
			return nil
		}
		pdu = a.handleSet(msg.PDU)
	case snmp.InformRequest:
		// An Inform is acknowledged by echoing it back as a Response.
		pdu = &snmp.PDU{RequestID: msg.PDU.RequestID, VarBinds: msg.PDU.VarBinds}
	default:
		// Traps and anything else receive no response.
		return nil
	}
	return a.encodeResponse(msg, pdu)
}

// encodeResponse renders a PDU as a Response datagram and drops it when
// encoding fails or the result exceeds the size limit.
func (a *Agent) encodeResponse(req *snmp.Message, pdu *snmp.PDU) []byte {
	pdu.Type = snmp.ResponsePDU
	pdu.RequestID = req.PDU.RequestID
	data, err := snmp.EncodeMessage(
		&snmp.Message{Version: snmp.Version2c, Community: req.Community, PDU: pdu},
	)
	if err != nil || len(data) > MaxMessageSize {
		return nil
	}
	return data
}

func errorPDU(req *snmp.PDU, status snmp.ErrorStatus, index int) *snmp.PDU {
	return &snmp.PDU{
		RequestID:   req.RequestID,
		ErrorStatus: status,
		ErrorIndex:  index,
		VarBinds:    req.VarBinds,
	}
}

func (a *Agent) handleGet(req *snmp.PDU) *snmp.PDU {
	out := make([]snmp.VarBind, 0, len(req.VarBinds))
	for i, vb := range req.VarBinds {
		value, _, _, ok := a.mib.Get(vb.Name)
		if !ok {
			return errorPDU(req, snmp.NoSuchName, i+1)
		}
		out = append(out, snmp.VarBind{Name: vb.Name, Value: toSNMPValue(value)})
	}
	return &snmp.PDU{RequestID: req.RequestID, VarBinds: out}
}

func (a *Agent) handleGetNext(req *snmp.PDU) *snmp.PDU {
	out := make([]snmp.VarBind, 0, len(req.VarBinds))
	for i, vb := range req.VarBinds {
		name, value, ok := a.mib.GetNext(vb.Name)
		if !ok {
			return errorPDU(req, snmp.NoSuchName, i+1)
		}
		out = append(out, snmp.VarBind{Name: name, Value: toSNMPValue(value)})
	}
	return &snmp.PDU{RequestID: req.RequestID, VarBinds: out}
}

func (a *Agent) handleSet(req *snmp.PDU) *snmp.PDU {
	items := make([]mib.SetItem, 0, len(req.VarBinds))
	for _, vb := range req.VarBinds {
		items = append(items, mib.SetItem{Name: vb.Name, Value: fromSNMPValue(vb.Value)})
	}
	if err := a.mib.ApplySet(items); err != nil {
		var setErr *mib.SetError
		if errors.As(err, &setErr) {
			return errorPDU(req, mapSetError(setErr.Err), setErr.Index)
		}
		return errorPDU(req, snmp.GenErr, 1)
	}
	if a.persist != nil {
		if err := a.persist(); err != nil {
			return errorPDU(req, snmp.GenErr, 1)
		}
	}
	// Success: echo the request varbinds in the response.
	return &snmp.PDU{RequestID: req.RequestID, VarBinds: req.VarBinds}
}

func mapSetError(err error) snmp.ErrorStatus {
	switch {
	case errors.Is(err, mib.ErrNotFound):
		return snmp.NoSuchName
	case errors.Is(err, mib.ErrReadOnly):
		return snmp.ReadOnly
	case errors.Is(err, mib.ErrBadType), errors.Is(err, mib.ErrBadLen), errors.Is(err, mib.ErrBadValue):
		return snmp.BadValue
	default:
		return snmp.GenErr
	}
}

// fromSNMPValue converts request named types into MIB named types. Counter32
// is intentionally not a valid set input for any writable object.
func fromSNMPValue(v any) any {
	switch x := v.(type) {
	case snmp.Integer32:
		return mib.Integer32(x)
	case snmp.OctetString:
		return mib.OctetString(append([]byte(nil), x...))
	case snmp.Gauge32:
		return mib.Gauge32(x)
	case snmp.Counter32:
		return mib.Counter32(x)
	default:
		return v
	}
}

// toSNMPValue maps a MIB value into the distinct snmp named types.
func toSNMPValue(v any) any {
	switch x := v.(type) {
	case mib.Integer32:
		return snmp.Integer32(x)
	case mib.OctetString:
		return snmp.OctetString(append([]byte(nil), x...))
	case mib.Counter32:
		return snmp.Counter32(x)
	case mib.Gauge32:
		return snmp.Gauge32(x)
	default:
		return snmp.Null{}
	}
}
