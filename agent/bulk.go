package agent

import (
	"github.com/guoyyit/snmp-agent-go/mib"
	"github.com/guoyyit/snmp-agent-go/oid"
	"github.com/guoyyit/snmp-agent-go/snmp"
)

// bulkPDU implements GetBulkRequest semantics:
//   - the first non-repeaters variable bindings produce one GetNext result
//     each and are emitted first;
//   - every remaining binding is advanced together for up to max-repetitions
//     rounds, emitted row by row (RFC 3416 order);
//   - a binding that leaves the MIB reports endOfMibView deterministically;
//   - an empty MIB yields endOfMibView for every requested binding;
//   - varbinds are dropped from the tail while the encoded response would
//     exceed the message-size budget.
func bulkPDU(req *snmp.PDU, m *mib.MIB, community string, maxSize int) *snmp.PDU {
	names := make([]oid.OID, len(req.VarBinds))
	for i, vb := range req.VarBinds {
		names[i] = vb.Name
	}
	nonRepeaters := req.NonRepeaters
	if nonRepeaters > len(names) {
		nonRepeaters = len(names)
	}

	cursors := make([]oid.OID, len(names))
	copy(cursors, names)
	var flat []snmp.VarBind

	// Non-repeaters: one GetNext result per binding.
	for i := 0; i < nonRepeaters; i++ {
		next, value, ok := m.GetNext(cursors[i])
		if !ok {
			flat = append(flat, snmp.VarBind{Name: cursors[i], Value: snmp.EndOfMibView})
		} else {
			flat = append(flat, snmp.VarBind{Name: next, Value: toSNMPValue(value)})
		}
	}

	// Repeaters: up to max-repetitions rounds over the remaining bindings.
	repeaterCount := len(names) - nonRepeaters
	for round := 0; round < req.MaxRepetitions && repeaterCount > 0; round++ {
		anyAdvanced := false
		for i := nonRepeaters; i < len(names); i++ {
			if cursors[i] == nil {
				flat = append(flat, snmp.VarBind{Name: names[i], Value: snmp.EndOfMibView})
				continue
			}
			next, value, ok := m.GetNext(cursors[i])
			if !ok {
				flat = append(flat, snmp.VarBind{Name: cursors[i], Value: snmp.EndOfMibView})
				cursors[i] = nil
				continue
			}
			flat = append(flat, snmp.VarBind{Name: next, Value: toSNMPValue(value)})
			cursors[i] = next
			anyAdvanced = true
		}
		if !anyAdvanced {
			break
		}
	}

	// Trim from the tail while the encoded message is too large.
	for len(flat) > 0 {
		candidate := &snmp.Message{
			Version:   snmp.Version2c,
			Community: community,
			PDU:       &snmp.PDU{Type: snmp.ResponsePDU, RequestID: req.RequestID, VarBinds: flat},
		}
		data, err := snmp.EncodeMessage(candidate)
		if err == nil && len(data) <= maxSize {
			break
		}
		flat = flat[:len(flat)-1]
	}

	return &snmp.PDU{RequestID: req.RequestID, VarBinds: flat}
}
