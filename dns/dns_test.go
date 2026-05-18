package dns

import (
	"net"
	"testing"
)

func BenchmarkParseDNSPacket(b *testing.B) {
	// A sample DNS query for google.com (A record)
	data := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Flags (Standard query)
		0x00, 0x01, // QDCOUNT
		0x00, 0x00, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
		0x06, 'g', 'o', 'o', 'g', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // Terminator
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
	}
	size := len(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseDNSPacket(data, size)
	}
}

func BenchmarkDNSPacketToBytes(b *testing.B) {
	packet := &DNSPacket{
		Header: DNSHeader{
			ID:      0x1234,
			QR:      1,
			OPCODE:  0,
			AA:      1,
			TC:      0,
			RD:      1,
			RA:      1,
			Z:       0,
			RCODE:   0,
			QDCOUNT: 1,
			ANCOUNT: 1,
			NSCOUNT: 0,
			ARCOUNT: 0,
		},
		Questions: []DNSQuestion{
			{
				Domain: "google.com.",
				Type:   RType.A,
				Class:  ClassType.IN,
			},
		},
		Answers: []DNSRecord{
			ADNSRecord{
				DNSRecordPreamble: DNSRecordPreamble{
					Name:  "google.com.",
					Type:  RType.A,
					Class: ClassType.IN,
					TTL:   300,
				},
				IP: net.ParseIP("142.250.190.46").To4(),
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = packet.ToBytes()
	}
}
