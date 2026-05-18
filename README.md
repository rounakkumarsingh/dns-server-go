# Go DNS Server

A high-performance, concurrent DNS recursive resolver built from scratch in Go.

## 🚀 Overview

This project is a fully functional DNS recursive resolver that handles UDP and TCP queries. It features a custom DNS packet parser, a sharded concurrent cache, and support for CNAME resolution, IPv6 nameservers, and more.

## ✨ Features

- **Full Recursive Resolution**: Resolves queries starting from root servers down to authoritative nameservers.
- **High-Performance Sharded Cache**: Optimized to minimize lock contention using a 32-shard architecture, achieving sub-100ns access times on multi-core systems.
- **UDP & TCP Support**: Automatically switches to TCP when responses are truncated.
- **EDNS0 Support**: Basic support for Extension Mechanisms for DNS.
- **Concurrency**: Per-request goroutine handling for massive throughput.
- **Smart Server Selection**: Prefers IPv4 for stability while supporting IPv6 fallback.
- **Comprehensive Benchmarking**: Includes detailed performance reports and benchmark suites.

## 📊 Performance

Performance is a first-class citizen in this implementation.

- **Cache Hit Latency**: ~84ns (16-core parallel access)
- **Processing Overhead**: ~1µs end-to-end (local cache hit)
- **Scalability**: Sharded architecture scales linearly with CPU cores.

For detailed metrics and optimization analysis, see [PERFORMANCE.md](./PERFORMANCE.md).

## 🛠 Getting Started

### Prerequisites
- Go 1.22 or later
- Docker (optional, for containerized deployment)

### Running Locally
1. Clone the repository:
   ```bash
   git clone https://github.com/rounakkumarsingh/dns-server-go.git
   cd dns-server-go
   ```
2. Run the server:
   ```bash
   go run .
   ```
   The server will start listening on `:1053` by default.

### Configuration
You can configure the server using environment variables:
- `DNS_CACHE_SHARDS`: Number of cache shards (default: 32). Set higher for high-concurrency environments.

## 🧪 Testing

### Functional Tests
Run the unit tests to ensure correctness:
```bash
go test -v ./...
```

### Benchmarks
Measure the performance on your machine:
```bash
go test -bench . -benchmem ./...
```

## 🐳 Docker Deployment

A `Dockerfile` is provided for easy deployment. For detailed instructions on Docker and cloud deployment, refer to [DEPLOYMENT.md](./DEPLOYMENT.md).

```bash
docker build -t dns-server .
docker run -p 1053:1053/udp dns-server
```

## 📜 License
This project is licensed under the MIT License - see the LICENSE file for details (if applicable).
