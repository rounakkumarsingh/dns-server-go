package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

func ParseDNSPacket(data []byte, size int) (*DNSPacket, error) {

	if size < 12 {
		return nil, fmt.Errorf("The size of the request is %d (invalid request)", size)
	}

	buf := data[:size]
	headerBytes := buf[:12]
	header := parseHeader(headerBytes)

	if header.TC == 1 {
		return nil, errors.New("Truncated DNS packet")
	}

	curr := 12 // Start after the header

	questions := make([]DNSQuestion, 0, header.QDCOUNT)
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

	answers := make([]DNSRecord, 0, header.ANCOUNT)
	for range header.ANCOUNT {
		if curr >= len(buf) {
			return nil, fmt.Errorf("Invalid ANCOUNT: %d, but buffer length is %d", header.ANCOUNT, len(buf))
		}
		answerRecord, end, err := parseRecord(buf, curr)
		if err != nil {
			return nil, err
		}
		answers = append(answers, answerRecord)
		curr = end
	}

	authoratives := make([]DNSRecord, 0, header.NSCOUNT)
	for range header.NSCOUNT {
		if curr >= len(buf) {
			return nil, fmt.Errorf("Invalid NSCOUNT: %d, but buffer length is %d", header.NSCOUNT, len(buf))
		}
		authoritativeRecord, end, err := parseRecord(buf, curr)
		if err != nil {
			return nil, err
		}
		authoratives = append(authoratives, authoritativeRecord)
		curr = end
	}

	additionals := make([]DNSRecord, 0, header.ARCOUNT)
	for range header.ARCOUNT {
		if curr >= len(buf) {
			return nil, fmt.Errorf("Invalid ARCOUNT: %d, but buffer length is %d", header.ARCOUNT, len(buf))
		}
		additionalRecord, end, err := parseRecord(buf, curr)
		if err != nil {
			return nil, err
		}
		additionals = append(additionals, additionalRecord)
		curr = end
	}

	return &DNSPacket{Header: *header, Questions: questions, Answers: answers, Authoratives: authoratives, Additional: additionals}, nil
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
	RCODE := DNSResponseCode((headerBytes[3]) & 0x0F)

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
	domainName, end, err := decodeDomainName(question, start)
	if err != nil {
		return nil, -1, err
	}

	if end+4 >= len(question) {
		return nil, -1, errors.New("Invalid question")
	}
	recordType := question[end+1 : end+3]
	class := question[end+3 : end+5]
	return &DNSQuestion{
		domainName,
		RecordType(binary.BigEndian.Uint16(recordType)),
		Class(binary.BigEndian.Uint16(class)),
	}, end + 5, nil
}

func parseRecord(record []byte, start int) (DNSRecord, int, error) {
	domainName, end, err := decodeDomainName(record, start)
	if err != nil {
		return nil, -1, err
	}

	if end+11 > len(record) {
		return nil, -1, errors.New("Invalid record")
	}

	recordType := binary.BigEndian.Uint16(record[end+1 : end+3])
	class := binary.BigEndian.Uint16(record[end+3 : end+5])
	ttl := binary.BigEndian.Uint32(record[end+5 : end+9])
	rdLength := binary.BigEndian.Uint16(record[end+9 : end+11])

	if end+11+int(rdLength) > len(record) {
		return nil, -1, errors.New("Invalid RDATA length")
	}

	rdata := record[end+11 : end+11+int(rdLength)]

	recordPreamble := DNSRecordPreamble{
		Name:  domainName,
		Type:  RecordType(recordType),
		Class: Class(class),
		TTL:   ttl,
	}

	switch recordType {
	case uint16(RType.A): // A record
		return ADNSRecord{DNSRecordPreamble: recordPreamble, IP: net.IP(rdata)}, end + 11 + int(rdLength), nil
	case uint16(RType.NS): // NS record
		host, _, _ := decodeDomainName(record, end+11)
		return NSDNSRecord{DNSRecordPreamble: recordPreamble, Host: host}, end + 11 + int(rdLength), nil
	case uint16(RType.CNAME): // CNAME record
		return CNAMERecord{DNSRecordPreamble: recordPreamble, CanonicalName: string(rdata)}, end + 11 + int(rdLength), nil
	case uint16(RType.TXT): // TXT record
		return TXTRecord{DNSRecordPreamble: recordPreamble, Text: string(rdata)}, end + 11 + int(rdLength), nil
	case uint16(RType.MX): // MX record
		preference := binary.BigEndian.Uint16(rdata[:2])
		exchange, _, _ := decodeDomainName(record, end+13)
		return MXRecord{DNSRecordPreamble: recordPreamble, Preference: preference, Exchange: exchange}, end + 11 + int(rdLength), nil
	case uint16(RType.AAAA): // AAAA record
		return AAAARecord{DNSRecordPreamble: recordPreamble, IP: net.IP(rdata)}, end + 11 + int(rdLength), nil
	case uint16(RType.SOA): // SOA record
		return SOARecord{DNSRecordPreamble: recordPreamble}, end + 11 + int(rdLength), nil
	case uint16(RType.OPT): // OPT record
		if domainName != "." {
			return nil, -1, errors.New("Invalid OPT record domain name")
		}

		// Time to get those options

		options := make([]EDNSOption, 0)

		i := 0
		for i+4 <= len(rdata) {
			optionCode := binary.BigEndian.Uint16(rdata[i : i+2])
			optionLength := binary.BigEndian.Uint16(rdata[i+2 : i+4])
			if i+4+int(optionLength) > len(rdata) {
				return nil, -1, errors.New("Invalid OPT record option length")
			}
			optionData := rdata[i+4 : i+4+int(optionLength)]
			i += 4 + int(optionLength)
			options = append(options, EDNSOption{
				Code: optionCode,
				Data: optionData,
			})
		}

		return OPTRecord{
			Name:     domainName,
			UDPSize:  class,
			ExtRCODE: uint8((ttl & 0xFF000000) >> 24),
			Version:  uint8((ttl & 0x00FF0000) >> 16),
			DO:       (ttl & 0x00008000) != 0,
			Z:        uint16((ttl & 0x00007FFF) >> 15),
			Options:  options,
		}, end + 11 + int(rdLength), nil
	default:
		return nil, -1, errors.New("Unknown record type")
	}
}
