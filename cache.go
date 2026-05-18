package main

import (
	"fmt"
	"hash/fnv"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/rounakkumarsingh/dns-server/dns"
)

type CacheEntry struct {
	Response dns.DNSPacket
	Expiry   time.Time
}

type CacheShard struct {
	mu      sync.RWMutex
	entries map[string]CacheEntry
}

type DNSCache struct {
	shards     []*CacheShard
	shardCount int
}

func NewDNSCache() *DNSCache {
	shardCount := 32
	if val, ok := os.LookupEnv("DNS_CACHE_SHARDS"); ok {
		if i, err := strconv.Atoi(val); err == nil && i > 0 {
			shardCount = i
		}
	}

	c := &DNSCache{
		shards:     make([]*CacheShard, shardCount),
		shardCount: shardCount,
	}

	for i := 0; i < shardCount; i++ {
		c.shards[i] = &CacheShard{
			entries: make(map[string]CacheEntry),
		}
	}

	return c
}

func (c *DNSCache) getShard(key string) *CacheShard {
	h := fnv.New32a()
	h.Write([]byte(key))
	return c.shards[uint(h.Sum32())%uint(c.shardCount)]
}

func (c *DNSCache) Get(domain string, recordType dns.RecordType) (dns.DNSPacket, bool) {
	key := fmt.Sprintf("%s:%s", domain, recordType)
	shard := c.getShard(key)

	shard.mu.RLock()
	defer shard.mu.RUnlock()

	entry, found := shard.entries[key]
	if found && time.Now().Before(entry.Expiry) {
		return entry.Response, true
	}
	return dns.DNSPacket{}, false
}

func (c *DNSCache) Set(domain string, recordType dns.RecordType, response dns.DNSPacket) {
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

	shard := c.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	shard.entries[key] = CacheEntry{
		Response: response,
		Expiry:   expiry,
	}
}

func (c *DNSCache) StartCleanup(interval time.Duration) {
	for i := 0; i < c.shardCount; i++ {
		shard := c.shards[i]
		go func(s *CacheShard) {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for range ticker.C {
				s.mu.Lock()
				for key, entry := range s.entries {
					if time.Now().After(entry.Expiry) {
						delete(s.entries, key)
					}
				}
				s.mu.Unlock()
			}
		}(shard)
	}
}
