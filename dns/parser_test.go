package dns

import (
	"bytes"
	"net"
	"testing"
)

func TestQuestionParse(t *testing.T) {
	questions := []DNSQuestion{
		{Domain: "Google.com", Type: RecordType.A, Class: ClassType.IN},
		{Domain: "boot.dev", Type: RecordType.CNAME, Class: ClassType.CS},
		{Domain: "dev.to", Type: RecordType.TXT, Class: ClassType.CH},
	}

	header := DNSHeader{ID: 31647, QR: 0, OPCODE: 0, AA: 0, TC: 0, RD: 1, RA: 0, Z: 0, AD: 1, CD: 0, RCODE: 0, QDCOUNT: 3, ANCOUNT: 0, NSCOUNT: 0, ARCOUNT: 1}

	record := []DNSRecord{{"google.com", RecordType.A, ClassType.IN, 60, []byte{23, 52, 214, 12, 255}}}

	dnsPacket := DNSPacket{Header: header, Questions: questions, Answers: []DNSRecord{}, Authoratives: []DNSRecord{}, Additional: record}

	actualPacket, err := dnsPacket.ToBytes()
	if err != nil {
		t.Errorf("Something is wrong while encoding man: %v", err)
	}

	decodedPacket, err := ParseDNSPacket(actualPacket, len(actualPacket), &net.UDPAddr{})
	if err != nil {
		t.Errorf("Something is wrong while decoding man: %v", err)
	}

	decodedBytes, err := decodedPacket.ToBytes()
	if err != nil {
		t.Errorf("Something is wrong while encoding decoded packet: %v", err)
	}
	if !bytes.Equal(actualPacket, decodedBytes) {
		t.Errorf("Expected: %v, but got: %v", actualPacket, decodedBytes)
	}

}
