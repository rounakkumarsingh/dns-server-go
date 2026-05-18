package main

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/rounakkumarsingh/dns-server/dns"
)

func TestCacheBasic(t *testing.T) {
	cache := NewDNSCache()
	domain := "example.com."
	recordType := dns.RType.A
	
	packet := dns.DNSPacket{
		Answers: []dns.DNSRecord{
			dns.ADNSRecord{
				DNSRecordPreamble: dns.DNSRecordPreamble{
					Name:  domain,
					Type:  recordType,
					Class: dns.ClassType.IN,
					TTL:   60,
				},
				IP: net.ParseIP("1.2.3.4"),
			},
		},
	}

	cache.Set(domain, recordType, packet)

	cached, found := cache.Get(domain, recordType)
	if !found {
		t.Fatal("Expected to find record in cache")
	}

	if len(cached.Answers) != 1 {
		t.Errorf("Expected 1 answer, got %d", len(cached.Answers))
	}
}

func TestCacheExpiration(t *testing.T) {
	cache := NewDNSCache()
	domain := "expire.com."
	recordType := dns.RType.A
	
	packet := dns.DNSPacket{
		Answers: []dns.DNSRecord{
			dns.ADNSRecord{
				DNSRecordPreamble: dns.DNSRecordPreamble{
					TTL: 1, // 1 second TTL
				},
			},
		},
	}

	cache.Set(domain, recordType, packet)

	// Should be there immediately
	_, found := cache.Get(domain, recordType)
	if !found {
		t.Fatal("Expected record to be in cache initially")
	}

	// Wait for expiration
	time.Sleep(2 * time.Second)

	_, found = cache.Get(domain, recordType)
	if found {
		t.Error("Expected record to be expired and not found")
	}
}

func TestCacheNegative(t *testing.T) {
	// Test caching of SOA records for NXDOMAIN (negative caching)
	cache := NewDNSCache()
	domain := "nonexistent.com."
	recordType := dns.RType.A

	packet := dns.DNSPacket{
		Authoratives: []dns.DNSRecord{
			dns.SOARecord{
				DNSRecordPreamble: dns.DNSRecordPreamble{
					Name: "com.",
					Type: dns.RType.SOA,
					TTL:  300,
				},
				MinimumTTL: 60,
			},
		},
	}

	cache.Set(domain, recordType, packet)

	_, found := cache.Get(domain, recordType)
	if !found {
		t.Error("Expected SOA record to be cached for negative response")
	}
}

func BenchmarkCacheGet(b *testing.B) {
	cache := NewDNSCache()
	domain := "google.com"
	recordType := dns.RType.A
	packet := dns.DNSPacket{
		Answers: []dns.DNSRecord{
			dns.ADNSRecord{
				DNSRecordPreamble: dns.DNSRecordPreamble{
					TTL: 300,
				},
			},
		},
	}
	cache.Set(domain, recordType, packet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Get(domain, recordType)
	}
}

func BenchmarkCacheSet(b *testing.B) {
	cache := NewDNSCache()
	domain := "google.com"
	recordType := dns.RType.A
	packet := dns.DNSPacket{
		Answers: []dns.DNSRecord{
			dns.ADNSRecord{
				DNSRecordPreamble: dns.DNSRecordPreamble{
					TTL: 300,
				},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Set(domain, recordType, packet)
	}
}

func BenchmarkCacheParallel(b *testing.B) {
	cache := NewDNSCache()
	recordType := dns.RType.A
	packet := dns.DNSPacket{
		Answers: []dns.DNSRecord{
			dns.ADNSRecord{
				DNSRecordPreamble: dns.DNSRecordPreamble{
					TTL: 300,
				},
			},
		},
	}

	domains := make([]string, 100)
	for i := 0; i < 100; i++ {
		domains[i] = fmt.Sprintf("domain%d.com", i)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			d := domains[i%100]
			if i%100 == 0 {
				cache.Set(d, recordType, packet)
			} else {
				cache.Get(d, recordType)
			}
			i++
		}
	})
}
