package dns

import (
	"encoding/binary"
	"fmt"
)

type DNSRecord struct {
	Name  string
	Type  Record
	Class Class
	TTL   uint32
	// RDLength uint16 (Can be deduced from len(RDATA))
	RDATA []byte
}

func (a *DNSRecord) ToBytes(offsetMap map[string]uint, offSet uint) []byte {
	buf := encodeDomainName(a.Name, offsetMap, offSet)

	typeBytes := make([]byte, 2)
	classBytes := make([]byte, 2)
	ttlBytes := make([]byte, 4)
	rdLengthBytes := make([]byte, 2)

	binary.BigEndian.PutUint16(typeBytes, uint16(a.Type))
	binary.BigEndian.PutUint16(classBytes, uint16(a.Class))
	binary.BigEndian.PutUint32(ttlBytes, a.TTL)
	binary.BigEndian.PutUint16(rdLengthBytes, uint16(len(a.RDATA)))

	buf = append(buf, typeBytes...)
	buf = append(buf, classBytes...)
	buf = append(buf, ttlBytes...)
	buf = append(buf, rdLengthBytes...)
	buf = append(buf, a.RDATA...)

	return buf
}

func (a *DNSRecord) String() string {
	return fmt.Sprintf("DNS Record:\n"+
		"  Name: %s\n"+
		"  Type: %s\n"+
		"  Class: %s\n"+
		"  TTL: %d\n"+
		"  RDATA Length: %d bytes",
		a.Name, a.Type, a.Class, a.TTL, len(a.RDATA))
}
