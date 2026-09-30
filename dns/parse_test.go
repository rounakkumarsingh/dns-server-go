package dns

import (
	"bytes"
	"errors"
	"net"
	"reflect"
	"testing"
)

func TestParseCNAMEWithCompressionPointer(t *testing.T) {
	data := []byte{
		0xab, 0xcd, // ID
		0x81, 0x80, // Flags (response, RD, RA)
		0x00, 0x01, // QDCOUNT
		0x00, 0x01, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
		// Question: www.example.com. A IN (name starts at offset 12)
		0x03, 'w', 'w', 'w',
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // offset 16
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x01, 0x00, 0x01,
		// Answer: <ptr to www.example.com.> CNAME IN TTL=300
		0xc0, 0x0c,
		0x00, 0x05, 0x00, 0x01,
		0x00, 0x00, 0x01, 0x2c,
		0x00, 0x06, // RDLENGTH
		0x03, 'c', 'd', 'n', 0xc0, 0x10, // cdn.<ptr to example.com.>
	}

	packet, err := ParseDNSPacket(data, len(data))
	if err != nil {
		t.Fatalf("ParseDNSPacket: %v", err)
	}
	if len(packet.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(packet.Answers))
	}
	cname, ok := packet.Answers[0].(CNAMERecord)
	if !ok {
		t.Fatalf("expected CNAMERecord, got %T", packet.Answers[0])
	}
	if cname.Name != "www.example.com." {
		t.Errorf("owner name = %q, want %q", cname.Name, "www.example.com.")
	}
	if cname.CanonicalName != "cdn.example.com." {
		t.Errorf("CanonicalName = %q, want %q", cname.CanonicalName, "cdn.example.com.")
	}
}

func TestParseUnknownRecordType(t *testing.T) {
	data := []byte{
		0x00, 0x01, // ID
		0x81, 0x80, // Flags
		0x00, 0x01, // QDCOUNT
		0x00, 0x02, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
		// Question: a.io. HTTPS IN
		0x01, 'a', 0x02, 'i', 'o', 0x00,
		0x00, 0x41, 0x00, 0x01,
		// Answer 1: a.io. HTTPS (type 65) IN TTL=60, opaque RDATA
		0xc0, 0x0c,
		0x00, 0x41, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x3c,
		0x00, 0x03,
		0x00, 0x01, 0x00,
		// Answer 2: a.io. A IN TTL=60 1.2.3.4 (must still be parsed after the unknown one)
		0xc0, 0x0c,
		0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x3c,
		0x00, 0x04,
		1, 2, 3, 4,
	}

	packet, err := ParseDNSPacket(data, len(data))
	if err != nil {
		t.Fatalf("ParseDNSPacket: %v", err)
	}
	if len(packet.Answers) != 2 {
		t.Fatalf("expected 2 answers, got %d", len(packet.Answers))
	}
	unknown, ok := packet.Answers[0].(UnknownRecord)
	if !ok {
		t.Fatalf("expected UnknownRecord, got %T", packet.Answers[0])
	}
	if unknown.Type != RecordType(65) || !bytes.Equal(unknown.Data, []byte{0x00, 0x01, 0x00}) {
		t.Errorf("unexpected unknown record: %+v", unknown)
	}
	if a, ok := packet.Answers[1].(ADNSRecord); !ok || !a.IP.Equal(net.IPv4(1, 2, 3, 4)) {
		t.Errorf("expected A 1.2.3.4 after unknown record, got %v", packet.Answers[1])
	}

	// Mutating the input buffer must not change the parsed record.
	data[len(data)-20] = 0xff
	if !bytes.Equal(unknown.Data, []byte{0x00, 0x01, 0x00}) {
		t.Errorf("UnknownRecord.Data aliases the input buffer")
	}
}

func TestPacketRoundTrip(t *testing.T) {
	preamble := func(name string, rtype RecordType, ttl uint32) DNSRecordPreamble {
		return DNSRecordPreamble{Name: name, Type: rtype, Class: ClassType.IN, TTL: ttl}
	}
	original := DNSPacket{
		Header: DNSHeader{ID: 0x1234, QR: 1, RD: 1, RA: 1, RCODE: DNSResponseCodeType.NameError,
			QDCOUNT: 1, ANCOUNT: 3, NSCOUNT: 1},
		Questions: []DNSQuestion{{Domain: "www.example.com.", Type: RType.A, Class: ClassType.IN}},
		Answers: []DNSRecord{
			CNAMERecord{DNSRecordPreamble: preamble("www.example.com.", RType.CNAME, 300), CanonicalName: "cdn.example.com."},
			PTRRecord{DNSRecordPreamble: preamble("4.3.2.1.in-addr.arpa.", RType.PTR, 300), Pointer: "host.example.com."},
			UnknownRecord{DNSRecordPreamble: preamble("www.example.com.", RecordType(65), 60), Data: []byte{1, 2, 3}},
		},
		Authoratives: []DNSRecord{
			SOARecord{
				DNSRecordPreamble: preamble("example.com.", RType.SOA, 3600),
				MName:             "ns1.example.com.",
				RName:             "hostmaster.example.com.",
				Serial:            2024010101,
				Refresh:           7200,
				Retry:             900,
				Expire:            1209600,
				MinimumTTL:        300,
			},
		},
	}

	data, err := original.ToBytes()
	if err != nil {
		t.Fatalf("ToBytes: %v", err)
	}
	parsed, err := ParseDNSPacket(data, len(data))
	if err != nil {
		t.Fatalf("ParseDNSPacket: %v", err)
	}

	if parsed.Header != original.Header {
		t.Errorf("header mismatch:\n got %+v\nwant %+v", parsed.Header, original.Header)
	}
	if !reflect.DeepEqual(parsed.Answers, original.Answers) {
		t.Errorf("answers mismatch:\n got %v\nwant %v", parsed.Answers, original.Answers)
	}
	if !reflect.DeepEqual(parsed.Authoratives, original.Authoratives) {
		t.Errorf("authorities mismatch:\n got %v\nwant %v", parsed.Authoratives, original.Authoratives)
	}
}

func TestDecodeDomainNameRejectsPointerLoops(t *testing.T) {
	header := []byte{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	tests := map[string][]byte{
		// "a" followed by a pointer back to the start of the same name.
		"self loop": {0x01, 'a', 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01},
		// A pointer to itself.
		"pointer to itself": {0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01},
		// A forward pointer.
		"forward pointer": {0xc0, 0x0e, 0x01, 'a', 0x00, 0x00, 0x01, 0x00, 0x01},
	}
	for name, question := range tests {
		t.Run(name, func(t *testing.T) {
			data := append(append([]byte(nil), header...), question...)
			if _, err := ParseDNSPacket(data, len(data)); err == nil {
				t.Error("expected an error for a looping compression pointer")
			}
		})
	}
}

func TestParsePointerToPointer(t *testing.T) {
	data := []byte{
		0x00, 0x01, 0x81, 0x80,
		0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
		// Question: a.io. A IN (offset 12)
		0x01, 'a', 0x02, 'i', 'o', 0x00,
		0x00, 0x01, 0x00, 0x01,
		// Answer 1 (offset 22): name is a pointer to offset 12
		0xc0, 0x0c,
		0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 1, 1, 1, 1,
		// Answer 2: name is a pointer to answer 1's name, itself a pointer
		0xc0, 0x16,
		0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 2, 2, 2, 2,
	}
	packet, err := ParseDNSPacket(data, len(data))
	if err != nil {
		t.Fatalf("ParseDNSPacket: %v", err)
	}
	if got := packet.Answers[1].Preamble().Name; got != "a.io." {
		t.Errorf("answer 2 name = %q, want %q", got, "a.io.")
	}
}

func TestParseRejectsShortRDATA(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rtype byte
		rdata []byte
	}{
		{"A", 0x01, []byte{1, 2}},
		{"AAAA", 0x1c, []byte{1, 2, 3, 4}},
		{"MX", 0x0f, []byte{1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte{
				0x00, 0x01, 0x81, 0x80,
				0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
				0x01, 'a', 0x00,
				0x00, tc.rtype, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c,
				0x00, byte(len(tc.rdata)),
			}
			data = append(data, tc.rdata...)
			if _, err := ParseDNSPacket(data, len(data)); err == nil {
				t.Error("expected an error for short RDATA")
			}
		})
	}
}

func TestOPTRecordRoundTrip(t *testing.T) {
	original := DNSPacket{
		Header: DNSHeader{ID: 1, ARCOUNT: 1},
		Additional: []DNSRecord{
			OPTRecord{Name: ".", UDPSize: 1232, Version: 0, DO: true, Z: 0x1234,
				Options: []EDNSOption{{Code: 10, Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}}}},
		},
	}
	data, err := original.ToBytes()
	if err != nil {
		t.Fatalf("ToBytes: %v", err)
	}
	parsed, err := ParseDNSPacket(data, len(data))
	if err != nil {
		t.Fatalf("ParseDNSPacket: %v", err)
	}
	if !reflect.DeepEqual(parsed.Additional, original.Additional) {
		t.Errorf("OPT mismatch:\n got %+v\nwant %+v", parsed.Additional, original.Additional)
	}
}

func TestParseTruncatedReturnsErrTruncated(t *testing.T) {
	data := []byte{0x00, 0x01, 0x83, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := ParseDNSPacket(data, len(data)); !errors.Is(err, ErrTruncated) {
		t.Errorf("err = %v, want ErrTruncated", err)
	}
}
