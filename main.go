package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Well-known OIDs served by this agent.
var (
	oidSysDescr    = []int{1, 3, 6, 1, 2, 1, 1, 1, 0}
	oidSysObjectID = []int{1, 3, 6, 1, 2, 1, 1, 2, 0}
	oidSysUpTime   = []int{1, 3, 6, 1, 2, 1, 1, 3, 0}
	oidSysContact  = []int{1, 3, 6, 1, 2, 1, 1, 4, 0}
	oidSysName     = []int{1, 3, 6, 1, 2, 1, 1, 5, 0}
	oidSysLocation = []int{1, 3, 6, 1, 2, 1, 1, 6, 0}
	oidSysServices = []int{1, 3, 6, 1, 2, 1, 1, 7, 0}
	oidDemoCounter = []int{1, 3, 6, 1, 4, 1, 53864, 1, 1, 0}
	oidDemoGauge   = []int{1, 3, 6, 1, 4, 1, 53864, 1, 2, 0}
	oidDemoMessage = []int{1, 3, 6, 1, 4, 1, 53864, 1, 3, 0}
	oidSnmpTrap    = []int{1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0}
	oidColdStart   = []int{1, 3, 6, 1, 6, 3, 1, 1, 5, 1}
)

// buildMIB constructs the management information base.
func buildMIB() *mibStore {
	s := newMIBStore()
	s.add(&mibObject{oid: oidSysDescr, tag: tagOctetString,
		strVal: []byte("snmp-agent-go SNMPv2c agent")})
	s.add(&mibObject{oid: oidSysObjectID, tag: tagOID,
		oidVal: []int{1, 3, 6, 1, 4, 1, 53864, 1}})
	s.add(&mibObject{oid: oidSysUpTime, tag: tagTimeTicks})
	s.add(&mibObject{oid: oidSysContact, tag: tagOctetString,
		writable: true, maxLen: 255})
	s.add(&mibObject{oid: oidSysName, tag: tagOctetString,
		writable: true, maxLen: 255, strVal: []byte("snmp-agent-go")})
	s.add(&mibObject{oid: oidSysLocation, tag: tagOctetString,
		writable: true, maxLen: 255})
	s.add(&mibObject{oid: oidSysServices, tag: tagInteger, intVal: 72})
	s.add(&mibObject{oid: oidDemoCounter, tag: tagCounter32})
	s.add(&mibObject{oid: oidDemoGauge, tag: tagGauge32, writable: true})
	s.add(&mibObject{oid: oidDemoMessage, tag: tagOctetString,
		writable: true, maxLen: 64})
	return s
}

func main() {
	configPath := flag.String("config", "agent-config.json", "config file path")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	mib := buildMIB()
	// Restore persisted writable objects before serving anything, so no
	// intermediate state is ever exposed to managers.
	if err := loadState(cfg.StatePath, mib); err != nil {
		log.Fatalf("restore state: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()

	a := newAgent(cfg, mib)
	go a.tickCounters(ctx, oidSysUpTime, 100, time.Second)
	go a.tickCounters(ctx, oidDemoCounter, 1, time.Second)

	// Announce ourselves once the socket is about to come up.
	go func() {
		time.Sleep(100 * time.Millisecond)
		a.trap.sendTrap([]varbind{
			{oid: oidSysUpTime, tag: tagTimeTicks, value: uint32(0)},
			{oid: oidSnmpTrap, tag: tagOID, value: oidColdStart},
		})
	}()

	if err := a.serve(ctx); err != nil {
		log.Fatalf("serve: %v", err)
	}
	a.shutdown()
	log.Println("snmp-agent-go: stopped")
}
