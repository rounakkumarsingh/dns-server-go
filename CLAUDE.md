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

Tests never touch the network: `resolver_test.go` swaps the package-level `sendQuery` (normally `query`) for canned upstream responses via `fakeUpstream`, `serve` is tested against a loopback UDP socket, and `query_test.go` runs `query` itself against a loopback fake nameserver (UDP + TCP on one port) by overriding `upstreamPort`. Codec tests live in `dns/parse_test.go` (hand-built wire bytes plus a `ToBytes` → `ParseDNSPacket` round trip); `dns/dns_test.go` holds benchmarks. Benchmark numbers quoted in `README.md` / `PERFORMANCE.md` come from these benchmarks — update those docs if you change cache/handler performance characteristics.

`DNS_CACHE_SHARDS` env var sets the cache shard count (default 32).

## Architecture

Two packages:

- **`dns/`** — wire-format codec. `ParseDNSPacket` (`parse.go`) decodes bytes into `DNSPacket` (Header, Questions, Answers, `Authoratives` [sic], Additional); `DNSPacket.ToBytes` encodes back. Records implement the `DNSRecord` interface (`Preamble()`, `ToBytes(offsetMap, offset)`, `String()`) in `dns_record.go`; callers type-switch on concrete types (`ADNSRecord`, `NSDNSRecord`, `CNAMERecord`, `SOARecord`, `OPTRecord`, …). Enum-like constants are exposed as struct-valued vars: `dns.RType.A`, `dns.ClassType.IN`, `dns.DNSResponseCodeType.NameError`.
- **`main` (root)** — `main.go`'s `serve` reads UDP queries into one reused buffer, copies each packet, and handles it in its own goroutine (with a per-goroutine `recover`); `handler.go` holds `handlePacket` → cache lookup → `resolve`; `cache.go` is the sharded TTL cache; `errors.go` defines `RESCODEError`, used to propagate an upstream RCODE (e.g. NXDOMAIN) into the client response.

Resolution flow (`handler.go`): `resolve` starts at a random root server (`RootServers`, IPv4 preferred by `getRandomDNSServer`) and recurses (depth limit 10) by following NS referrals from the Authority section, using glue A/AAAA records from Additional. It returns `(answers, soaRecords, err)`: SOA records come from negative responses (NXDOMAIN, or NODATA — NOERROR with no answer and no NS referral) and end up in the client response's Authority section for negative caching. CNAME chains are followed within the answer section first; if the chain ends without the requested type, the final target is re-resolved from the root and the chain prepended. Upstream queries go through the `sendQuery` variable. `query` sends over UDP and falls back to TCP (`queryOverTCP`, 2-byte length prefix) when parsing returns `dns.ErrTruncated`; both paths use `upstreamTimeout`. `validateResponse` rejects upstream packets whose ID, QR bit or question doesn't match the query (anti-spoofing). Glueless NS lookups in `getRandomDNSServer` take the caller's depth, so they count toward the same limit. Only single-question queries are accepted; client OPT (EDNS0) records are echoed back in Additional.

Cache (`cache.go`): key is `"<domain>:<type>"`, FNV-32a hashed onto N shards each with its own `RWMutex`; TTL = min answer TTL (falls back to min(SOA TTL, SOA `MinimumTTL`) when no answers, per RFC 2308; TTL 0 is not cached). NXDOMAIN and NODATA responses carrying an SOA are cached; SERVFAIL and other errors are not. Each shard runs its own cleanup goroutine. Cached responses have their header ID rewritten on hit.

### Codec invariants to preserve

- `DNSPacket.ToBytes` errors if `QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT` don't match slice lengths — update header counts whenever you modify sections.
- Name compression on encode uses a shared `offsetMap` (suffix → byte offset) threaded through every `ToBytes` call; the `offSet` argument must be the current length of the output buffer.
- `decodeDomainName` returns the index of the terminating byte (null or last pointer byte), not one past it — `parseRecord` therefore reads the type at `end+1`.
- Record types without a case in `parseRecord` become `UnknownRecord` (RDATA copied verbatim and re-emitted as-is). Adding a record type means: constant in `record.go`, struct + methods in `dns_record.go`, a case in `parseRecord`. Domain names inside RDATA (CNAME, NS, PTR, MX, SOA) must be decoded with `decodeDomainName` against the whole packet, since they may contain compression pointers.
- `decodeDomainName` only accepts compression pointers to offsets before the start of the name being decoded; this is what stops crafted pointer loops from overflowing the stack (a fatal error `recover` can't catch). Keep that guarantee if you touch it.
- Parsers that index into RDATA directly need a minimum length in `fixedRDataLength`.
- Parsed records must not alias the input buffer where it matters (`UnknownRecord` copies its data); `serve` also copies each packet before handing it off.

## Deployment

`Dockerfile` is a multi-stage build (golang → alpine). The server listens on UDP `:1053` (hard-coded in `main.go`, no TCP listener): `docker run -p 1053:1053/udp dns-server`.
