package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/rounakkumarsingh/dns-server/dns"
)

type CacheEntry struct {
	Response dns.DNSPacket
	Expiry   time.Time
}

type DNSCache struct {
	mu      sync.RWMutex
	entries map[string]CacheEntry
}

func NewDNSCache() *DNSCache {
	return &DNSCache{
		entries: make(map[string]CacheEntry),
	}
}

func (c *DNSCache) Get(domain string, recordType dns.RecordType) (dns.DNSPacket, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	key := fmt.Sprintf("%s:%s", domain, recordType)
	entry, found := c.entries[key]
	if found && time.Now().Before(entry.Expiry) {
		return entry.Response, true
	}
	return dns.DNSPacket{}, false
}

func (c *DNSCache) Set(domain string, recordType dns.RecordType, response dns.DNSPacket) {
	c.mu.Lock()
	defer c.mu.Unlock()

	minTTL := -1

	for _, ans := range response.Answers {
		ttl := int(ans.Preamble().TTL)
		if minTTL == -1 || ttl < minTTL {
			minTTL = ttl
		}
	}

	if minTTL == 0 {
		return
	}

	if minTTL == -1 {
		// No answers, check authority records for SOA
		for _, auth := range response.Authoratives {
			if soa, ok := auth.(dns.SOARecord); ok {
				minTTL = int(soa.MinimumTTL)
				break
			}
		}
	}

	if minTTL == -1 {
		// No TTL found in answers or authority records, don't cache
		return
	}

	key := fmt.Sprintf("%s:%s", domain, recordType)
	expiry := time.Now().Add(time.Duration(minTTL) * time.Second)
	c.entries[key] = CacheEntry{
		Response: response,
		Expiry:   expiry,
	}
}

func (c *DNSCache) StartCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			c.mu.Lock()
			for key, entry := range c.entries {
				if time.Now().After(entry.Expiry) {
					delete(c.entries, key)
				}
			}
			c.mu.Unlock()
		}
	}()
}
