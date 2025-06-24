package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

func ParseDNSPacket(data []byte, size int, source *net.UDPAddr) (*DNSPacket, error) {

	if size < 12 {
		return nil, fmt.Errorf("The size of the request from %s is %d (invalid request)", source.String(), size)
	}

	buf := data[:size]
	headerBytes := buf[:12]
	header := parseHeader(headerBytes)

	questions := make([]DNSQuestion, 0, header.QDCOUNT)

	curr := 12 // Start after the header

	for range header.QDCOUNT {
		if curr >= len(buf) {
			return nil, fmt.Errorf("Invalid QDCOUNT: %d, but buffer length is %d", header.QDCOUNT, len(buf))
		}
		question, end, err := parseQuestion(buf, curr)
		if err != nil {
			return nil, err
		}
		questions = append(questions, *question)
		curr = end
	}

	additionals := make([]DNSRecord, 0, header.ARCOUNT)

	for range header.ARCOUNT {
		if curr >= len(buf) {
			return nil, fmt.Errorf("Invalid ARCOUNT: %d, but buffer length is %d", header.ARCOUNT, len(buf))
		}
		record, end, err := parseRecord(buf, curr)
		if err != nil {
			return nil, err
		}
		additionals = append(additionals, *record)
		curr = end
	}

	return &DNSPacket{Header: *header, Questions: questions, Additional: additionals}, nil
}

func parseHeader(headerBytes []byte) *DNSHeader {

	QR := (headerBytes[2] >> 7) & 1
	OPCODE := (headerBytes[2] >> 3) & 0x0F
	AA := (headerBytes[2] >> 2) & 1
	TC := (headerBytes[2] >> 1) & 1
	RD := (headerBytes[2]) & 1

	RA := (headerBytes[3] >> 7) & 1
	Z := (headerBytes[3] >> 6) & 0x1
	AD := (headerBytes[3] >> 5) & 1
	CD := (headerBytes[3] >> 4) & 1
	RCODE := (headerBytes[3]) & 0x0F

	return &DNSHeader{
		ID:      binary.BigEndian.Uint16(headerBytes[0:2]),
		QR:      QR,
		OPCODE:  OPCODE,
		AA:      AA,
		TC:      TC,
		RD:      RD,
		RA:      RA,
		Z:       Z,
		AD:      AD,
		CD:      CD,
		RCODE:   RCODE,
		QDCOUNT: binary.BigEndian.Uint16(headerBytes[4:6]),
		ANCOUNT: binary.BigEndian.Uint16(headerBytes[6:8]),
		NSCOUNT: binary.BigEndian.Uint16(headerBytes[8:10]),
		ARCOUNT: binary.BigEndian.Uint16(headerBytes[10:12]),
	}
}

func parseQuestion(question []byte, start int) (*DNSQuestion, int, error) {
	encodedDomainName := question[start:]
	domainName, end, err := decodeDomainName(encodedDomainName)
	if err != nil {
		return nil, -1, err
	}

	if start+end+4 >= len(question) {
		return nil, -1, errors.New("Invalid question")
	}
	recordType := question[start+end+1 : start+end+3]
	class := question[start+end+3 : start+end+5]
	return &DNSQuestion{
		domainName,
		Record(binary.BigEndian.Uint16(recordType)),
		Class(binary.BigEndian.Uint16(class)),
	}, start + end + 5, nil
}

func parseRecord(record []byte, start int) (*DNSRecord, int, error) {
	encodedDomainName := record[start:]
	domainName, end, err := decodeDomainName(encodedDomainName)
	if err != nil {
		return nil, -1, err
	}

	if start+end+11 > len(record) {
		return nil, -1, errors.New("Invalid record")
	}

	recordType := binary.BigEndian.Uint16(record[start+end+1 : start+end+3])
	class := binary.BigEndian.Uint16(record[start+end+3 : start+end+5])
	ttl := binary.BigEndian.Uint32(record[start+end+5 : start+end+9])
	rdLength := binary.BigEndian.Uint16(record[start+end+9 : start+end+11])

	if start+end+11+int(rdLength) > len(record) {
		return nil, -1, errors.New("Invalid RDATA length")
	}

	rdata := record[start+end+11 : start+end+11+int(rdLength)]
	return &DNSRecord{
		Name:  domainName,
		Type:  Record(recordType),
		Class: Class(class),
		TTL:   ttl,
		RDATA: rdata,
	}, start + end + 11 + int(rdLength), nil
}
