package snmp

import "github.com/guoyyit/snmp-agent-go/oid"

const Version2c = 1

// PDUType is the ASN.1 context-specific PDU tag.
type PDUType byte

const (
	GetRequest     PDUType = 0xA0
	GetNextRequest PDUType = 0xA1
	ResponsePDU    PDUType = 0xA2
	SetRequest     PDUType = 0xA3
	GetBulkRequest PDUType = 0xA5
	InformRequest  PDUType = 0xA6
	TrapV2         PDUType = 0xA7
)

// SNMPv2 error-status codes.
type ErrorStatus int

const (
	NoError    ErrorStatus = 0
	TooBig     ErrorStatus = 1
	NoSuchName ErrorStatus = 2
	BadValue   ErrorStatus = 3
	ReadOnly   ErrorStatus = 4
	GenErr     ErrorStatus = 5
)

// VarBind exception tags (SNMPv2, context-specific, primitive).
type Exception byte

const (
	NoSuchObject   Exception = 0x80
	NoSuchInstance Exception = 0x81
	EndOfMibView   Exception = 0x82
)

// Value syntax types. Counter32/Gauge32 are distinct so semantics never mix.
type (
	Integer32   int32
	OctetString []byte
	Counter32   uint32
	Gauge32     uint32
	TimeTicks   uint32
	Null        struct{}
)

type VarBind struct {
	Name  oid.OID
	Value any
}

type PDU struct {
	Type           PDUType
	RequestID      int32
	NonRepeaters   int
	MaxRepetitions int
	ErrorStatus    ErrorStatus
	ErrorIndex     int
	VarBinds       []VarBind
}

type Message struct {
	Version   int
	Community string
	PDU       *PDU
}
