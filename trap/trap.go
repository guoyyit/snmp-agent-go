package trap

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/guoyyit/snmp-agent-go/snmp"
)

// Default transport tunables.
const (
	DefaultTimeout     = 200 * time.Millisecond
	DefaultMaxAttempts = 5
)

var (
	ErrNoManager  = errors.New("trap: no manager configured")
	ErrNoAck      = errors.New("trap: inform not acknowledged")
	ErrBadAddress = errors.New("trap: invalid manager address")
)

// Sender transmits SNMPv2c Trap and InformRequest PDUs to a single manager
// whose address can change at runtime.
type Sender struct {
	mu          sync.Mutex
	managerAddr *net.UDPAddr
	conn        *net.UDPConn
	timeout     time.Duration
	maxAttempts int
	nextID      int32
}

// New creates a Sender bound to an ephemeral local UDP port.
func New() (*Sender, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	return &Sender{conn: conn, timeout: DefaultTimeout, maxAttempts: DefaultMaxAttempts, nextID: 1}, nil
}

// Close releases the underlying socket.
func (s *Sender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	return err
}

// SetManager updates the current manager address. Every pending and future
// retransmission targets this latest address; older addresses are forgotten.
func (s *Sender) SetManager(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return ErrBadAddress
	}
	s.mu.Lock()
	s.managerAddr = udpAddr
	s.mu.Unlock()
	return nil
}

func (s *Sender) manager() *net.UDPAddr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.managerAddr
}

// SendTrap transmits an unacknowledged SNMPv2c Trap PDU.
func (s *Sender) SendTrap(community string, pdu *snmp.PDU) error {
	dst := s.manager()
	if dst == nil {
		return ErrNoManager
	}
	pdu.Type = snmp.TrapV2
	return s.write(community, pdu, dst)
}

// SendInform transmits an InformRequest and blocks until an acknowledgement
// arrives or all attempts are exhausted. The manager address is re-read for
// every attempt, so retransmissions always target the latest manager.
func (s *Sender) SendInform(community string, pdu *snmp.PDU) error {
	pdu.Type = snmp.InformRequest
	id := pdu.RequestID

	for attempt := 0; attempt < s.maxAttempts; attempt++ {
		dst := s.manager()
		if dst == nil {
			return ErrNoManager
		}
		if err := s.write(community, pdu, dst); err != nil {
			return err
		}
		deadline := time.Now().Add(s.timeout)
		for {
			s.mu.Lock()
			conn := s.conn
			s.mu.Unlock()
			if conn == nil {
				return ErrNoAck
			}
			_ = conn.SetReadDeadline(deadline)
			buf := make([]byte, 2048)
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					break // retransmit
				}
				return ErrNoAck
			}
			if s.matchesAck(buf[:n], community, id) {
				return nil
			}
			// Duplicate, stray, or unparseable datagram: keep waiting until
			// the deadline, never count it as an acknowledgement.
			if time.Now().After(deadline) {
				break
			}
		}
	}
	return ErrNoAck
}

// matchesAck validates that a datagram is the Response acknowledging this
// exact inform request id. A duplicate ack matches the same way, but the
// caller has already returned and therefore cannot re-report the inform.
func (s *Sender) matchesAck(data []byte, community string, id int32) bool {
	msg, err := snmp.DecodeMessage(data)
	if err != nil || msg == nil || msg.PDU == nil {
		return false
	}
	return msg.Community == community &&
		msg.PDU.Type == snmp.ResponsePDU &&
		msg.PDU.RequestID == id
}

func (s *Sender) write(community string, pdu *snmp.PDU, dst *net.UDPAddr) error {
	data, err := snmp.EncodeMessage(&snmp.Message{
		Version: snmp.Version2c, Community: community, PDU: pdu,
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn == nil {
		return ErrNoAck
	}
	_, err = conn.WriteToUDP(data, dst)
	return err
}

// Attempts exposes the retry budget for tests/configuration.
func (s *Sender) Attempts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxAttempts
}

// SetRetryPolicy overrides timeout and total attempt count.
func (s *Sender) SetRetryPolicy(timeout time.Duration, maxAttempts int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if timeout > 0 {
		s.timeout = timeout
	}
	if maxAttempts > 0 {
		s.maxAttempts = maxAttempts
	}
}
