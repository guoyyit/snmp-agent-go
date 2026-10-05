package agent

import (
	"context"
	"net"
	"sync"

	"github.com/guoyyit/snmp-agent-go/config"
	"github.com/guoyyit/snmp-agent-go/mib"
)

// Agent is the SNMPv2c UDP agent. It does not open its socket until
// construction and state restoration have fully completed, so no request can
// ever observe a partially restored MIB.
type Agent struct {
	mu      sync.RWMutex
	mib     *mib.MIB
	cfg     *config.Config
	conn    *net.UDPConn
	persist func() error
	done    chan struct{}
	ready   chan struct{}
	onPeer  func(string)
}

// SetPeerObserver registers a callback invoked with the source address of
// every accepted request. It lets the trap sender always target the manager
// that most recently contacted the agent.
func (a *Agent) SetPeerObserver(fn func(addr string)) {
	a.mu.Lock()
	a.onPeer = fn
	a.mu.Unlock()
}

// New wires the MIB and configuration. A nil persist hook disables
// persistence (used in tests).
func New(m *mib.MIB, cfg *config.Config, persist func() error) *Agent {
	return &Agent{
		mib:     m,
		cfg:     cfg,
		persist: persist,
		done:    make(chan struct{}),
		ready:   make(chan struct{}),
	}
}

// Done closes when Serve has fully exited and the socket is released.
func (a *Agent) Done() <-chan struct{} { return a.done }

// Ready closes once the listening socket is bound.
func (a *Agent) Ready() <-chan struct{} { return a.ready }

// LocalAddr reports the bound address after Serve starts.
func (a *Agent) LocalAddr() *net.UDPAddr {
	<-a.ready
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.conn == nil {
		return nil
	}
	return a.conn.LocalAddr().(*net.UDPAddr)
}

// Serve binds the loopback UDP endpoint and serves until ctx is cancelled.
func (a *Agent) Serve(ctx context.Context) error {
	defer close(a.done)
	addr, err := net.ResolveUDPAddr("udp4", a.cfg.ListenAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.conn = conn
	a.mu.Unlock()
	close(a.ready)
	defer conn.Close()

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	buf := make([]byte, MaxMessageSize)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		func() {
			// A malformed packet must never take the server down.
			defer func() { _ = recover() }()
			packet := make([]byte, n)
			copy(packet, buf[:n])
			if resp := a.handle(packet, src); resp != nil {
				_, _ = conn.WriteToUDP(resp, src)
			}
		}()
	}
}
