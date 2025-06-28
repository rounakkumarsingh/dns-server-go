package dns

import (
	"encoding/binary"
	"fmt"
)

type DNSQuestion struct {
	Domain string
	Type   Record
	Class  Class
}

func (q *DNSQuestion) ToBytes(offsetMap map[string]uint, offSet uint) []byte {
	// Encoding the domain name
	buf := encodeDomainName(q.Domain, offsetMap, offSet)

	typeBytes := make([]byte, 2)
	classBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, uint16(q.Type))
	binary.BigEndian.PutUint16(classBytes, uint16(q.Class))

	buf = append(buf, typeBytes...)
	buf = append(buf, classBytes...)
	return buf
}

func (q DNSQuestion) String() string {
	return fmt.Sprintf("Domain: %s, Type: %s, Class: %s", q.Domain, q.Type, q.Class)
}
