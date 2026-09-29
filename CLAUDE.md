# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

A recursive DNS resolver written from scratch in Go (no third-party DNS libraries, no external dependencies — `go.mod` has no requires). Module path is `github.com/rounakkumarsingh/dns-server` (note: differs from the repo name `dns-server-go`). Go 1.24+ (uses `for range <int>`).

## Commands

```bash
go run .                                   # start server on UDP :1053
go build -o dns-server .
go vet ./...
go test -v ./...                           # all tests
go test -run TestCacheExpiration -v .      # single test (root package)
go test -bench . -benchmem ./...           # all benchmarks
go test -run '^$' -bench BenchmarkCacheParallel -cpu 1,4,16 .   # one benchmark, scaling across cores
dig @127.0.0.1 -p 1053 example.com A       # manual query against a running server
```

Tests in the root package (`cache_test.go`, `handler_test.go`) only exercise the cache and the cache-hit path of `handlePacket`; anything that reaches `resolve` hits real root servers over the network. `dns/dns_test.go` contains only benchmarks. Benchmark numbers quoted in `README.md` / `PERFORMANCE.md` come from these benchmarks — update those docs if you change cache/handler performance characteristics.

`DNS_CACHE_SHARDS` env var sets the cache shard count (default 32).

## Architecture

Two packages:

- **`dns/`** — wire-format codec. `ParseDNSPacket` (`parse.go`) decodes bytes into `DNSPacket` (Header, Questions, Answers, `Authoratives` [sic], Additional); `DNSPacket.ToBytes` encodes back. Records implement the `DNSRecord` interface (`Preamble()`, `ToBytes(offsetMap, offset)`, `String()`) in `dns_record.go`; callers type-switch on concrete types (`ADNSRecord`, `NSDNSRecord`, `CNAMERecord`, `SOARecord`, `OPTRecord`, …). Enum-like constants are exposed as struct-valued vars: `dns.RType.A`, `dns.ClassType.IN`, `dns.DNSResponseCodeType.NameError`.
- **`main` (root)** — `main.go` runs a UDP listener with a goroutine per request; `handler.go` holds `handlePacket` → cache lookup → `resolve`; `cache.go` is the sharded TTL cache; `errors.go` defines `RESCODEError`, used to propagate an upstream RCODE (e.g. NXDOMAIN) into the client response.

Resolution flow (`handler.go`): `resolve` starts at a random root server (`RootServers`, IPv4 preferred by `getRandomDNSServer`) and recurses (depth limit 10) by following NS referrals from the Authority section, using glue A/AAAA records from Additional. CNAMEs are chased by re-resolving the target and prepending the CNAME record. `query` sends over UDP with a 10s deadline and falls back to TCP (`queryOverTCP`, 2-byte length prefix) when parsing fails with the exact error string `"Truncated DNS packet"` — changing that message in `dns/parse.go` breaks TCP fallback. Only single-question queries are accepted; client OPT (EDNS0) records are echoed back in Additional.

Cache (`cache.go`): key is `"<domain>:<type>"`, FNV-32a hashed onto N shards each with its own `RWMutex`; TTL = min answer TTL (falls back to SOA `MinimumTTL` when no answers; TTL 0 is not cached). Each shard runs its own cleanup goroutine. Cached responses have their header ID rewritten on hit.

### Codec invariants to preserve

- `DNSPacket.ToBytes` errors if `QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT` don't match slice lengths — update header counts whenever you modify sections.
- Name compression on encode uses a shared `offsetMap` (suffix → byte offset) threaded through every `ToBytes` call; the `offSet` argument must be the current length of the output buffer.
- `decodeDomainName` returns the index of the terminating byte (null or last pointer byte), not one past it — `parseRecord` therefore reads the type at `end+1`.
- `parseRecord` returns an error for unrecognized record types, which fails the whole packet. Adding a record type means: constant in `record.go`, struct + methods in `dns_record.go`, a case in `parseRecord`.
- `SOARecord` is parsed with only its preamble (RDATA fields are not decoded), so `MinimumTTL` is currently always 0 for parsed SOAs.

## Deployment

`Dockerfile` is a multi-stage build (golang → alpine). Note the server listens on `:1053` (hard-coded in `main.go`) while the Dockerfile `EXPOSE`s 53/udp; map ports accordingly (`docker run -p 1053:1053/udp`).
