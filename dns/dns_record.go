package dns

import "encoding/binary"

type DNSRecord struct {
	Name  string
	Type  Record
	Class Class
	TTL   uint32
	// RDLength uint16 (Can be deduced from len(RDATA))
	RDATA []byte
}

func (a *DNSRecord) ToBytes() []byte {
	buf := encodeDomainName(a.Name)

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

func NewDNSRecord(name string, recordType Record, class Class, ttl uint32, rdata []byte) DNSRecord {
	return DNSRecord{
		Name:  name,
		Type:  recordType,
		Class: class,
		TTL:   ttl,
		RDATA: rdata,
	}
}
