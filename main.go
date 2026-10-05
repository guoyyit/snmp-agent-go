package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/guoyyit/snmp-agent-go/agent"
	"github.com/guoyyit/snmp-agent-go/config"
	"github.com/guoyyit/snmp-agent-go/mib"
	"github.com/guoyyit/snmp-agent-go/oid"
	"github.com/guoyyit/snmp-agent-go/trap"
)

// syntaxNames maps config syntax tags to MIB syntaxes.
var syntaxNames = map[string]mib.Syntax{
	"Integer32":   mib.SyntaxInteger32,
	"OctetString": mib.SyntaxOctetString,
	"Counter32":   mib.SyntaxCounter32,
	"Gauge32":     mib.SyntaxGauge32,
}

// buildMIB registers the local management information tree.
func buildMIB() *mib.MIB {
	m := mib.New()
	reg := func(id, name, syntax string, access mib.Access, max int) {
		o, err := oid.Parse(id)
		if err != nil {
			log.Fatalf("bad OID %s: %v", id, err)
		}
		m.Register(mib.Object{OID: o, Name: name, Syntax: syntaxNames[syntax], Access: access, MaxOctets: max}, nil)
	}
	// System group
	reg("1.3.6.1.2.1.1.1.0", "sysDescr", "OctetString", mib.AccessReadWrite, 255)
	reg("1.3.6.1.2.1.1.3.0", "sysUpTime", "Counter32", mib.AccessReadOnly, 0)
	reg("1.3.6.1.2.1.1.4.0", "sysContact", "OctetString", mib.AccessReadWrite, 255)
	reg("1.3.6.1.2.1.1.5.0", "sysName", "OctetString", mib.AccessReadWrite, 255)
	// Interfaces table (two rows)
	for _, row := range []struct{ idx, id, descr string }{
		{"1", "1.3.6.1.2.1.2.2.1.1.1", "1.3.6.1.2.1.2.2.1.2.1"},
		{"2", "1.3.6.1.2.1.2.2.1.1.2", "1.3.6.1.2.1.2.2.1.2.2"},
	} {
		reg(row.id, "ifIndex."+row.idx, "Integer32", mib.AccessReadOnly, 0)
		reg(row.descr, "ifDescr."+row.idx, "OctetString", mib.AccessReadWrite, 255)
	}
	reg("1.3.6.1.2.1.2.2.1.10.1", "ifInOctets.1", "Counter32", mib.AccessReadOnly, 0)
	reg("1.3.6.1.2.1.2.2.1.10.2", "ifInOctets.2", "Counter32", mib.AccessReadOnly, 0)
	reg("1.3.6.1.2.1.2.2.1.5.1", "ifSpeed.1", "Gauge32", mib.AccessReadWrite, 0)
	reg("1.3.6.1.2.1.2.2.1.5.2", "ifSpeed.2", "Gauge32", mib.AccessReadWrite, 0)
	return m
}

func main() {
	configPath := flag.String("config", "snmp-agent.json", "path to persisted config/state file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	db := buildMIB()

	// Restore persisted writable values BEFORE the socket ever opens. Any
	// restart therefore presents either the old complete state or the new
	// complete state, never an intermediate one.
	restored := make(map[string]mib.StoredValue, len(cfg.Values))
	for k, v := range cfg.Values {
		syn, ok := syntaxNames[v.Syntax]
		if !ok {
			continue
		}
		raw, err := v.DecodeRaw()
		if err != nil {
			continue
		}
		restored[k] = mib.StoredValue{Syntax: syn, Raw: raw}
	}
	db.RestoreValues(restored)

	var saveMu sync.Mutex
	persist := func() error {
		saveMu.Lock()
		defer saveMu.Unlock()
		snapshot := db.WritableValues()
		values := make(map[string]config.PersistedValue, len(snapshot))
		for k, v := range snapshot {
			values[k] = config.NewPersistedValue(syntaxTagName(v.Syntax), v.Raw)
		}
		cfg.Values = values
		return cfg.Save(*configPath)
	}

	a := agent.New(db, cfg, persist)

	// Outgoing traps/informs target the manager that most recently contacted
	// us; retransmissions therefore always aim at the freshest address.
	sender, err := trap.New()
	if err != nil {
		log.Fatalf("trap sender: %v", err)
	}
	defer sender.Close()
	a.SetPeerObserver(func(addr string) { _ = sender.SetManager(addr) })

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("SNMPv2c agent listening on %s", cfg.ListenAddr)
	if err := a.Serve(ctx); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

func syntaxTagName(s mib.Syntax) string {
	for name, syn := range syntaxNames {
		if syn == s {
			return name
		}
	}
	return "OctetString"
}
