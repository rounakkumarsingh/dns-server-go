package main

import (
	"net"
	"testing"

	"github.com/rounakkumarsingh/dns-server/dns"
)

func BenchmarkHandlePacketCacheHit(b *testing.B) {
	cache := NewDNSCache()
	domain := "google.com."
	recordType := dns.RType.A
	
	packet := dns.DNSPacket{
		Header: dns.DNSHeader{
			ANCOUNT: 1,
		},
		Answers: []dns.DNSRecord{
			dns.ADNSRecord{
				DNSRecordPreamble: dns.DNSRecordPreamble{
					Name:  domain,
					Type:  recordType,
					Class: dns.ClassType.IN,
					TTL:   300,
				},
				IP: net.ParseIP("142.250.190.46").To4(),
			},
		},
	}
	cache.Set(domain, recordType, packet)

	// Sample query
	queryData := []byte{
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

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = handlePacket(queryData, cache)
	}
}
