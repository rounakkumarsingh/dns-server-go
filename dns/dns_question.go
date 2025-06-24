package dns

import (
	"encoding/binary"
)

type DNSQuestion struct {
	Domain string
	Type   Record
	Class  Class
}

func (q *DNSQuestion) ToBytes() []byte {
	// Encoding the domain name
	buf := encodeDomainName(q.Domain)

	typeBytes := make([]byte, 2)
	classBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, uint16(q.Type))
	binary.BigEndian.PutUint16(classBytes, uint16(q.Class))

	buf = append(buf, typeBytes...)
	buf = append(buf, classBytes...)
	return buf
}
