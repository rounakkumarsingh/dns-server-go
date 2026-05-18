# High-Performance Go DNS Resolver

A production-ready, recursive DNS resolver built from the ground up in Go, designed for extreme low-latency and high-concurrency environments.

## 🚀 Engineering Highlights

This project is a demonstration of high-performance system design, focusing on solving the common bottlenecks in concurrent network applications.

### ⚡ Sharded Cache (Solving Lock Contention)
The core optimization of this resolver is a custom **Sharded DNS Cache**. By splitting the global cache into 32 independent shards, each with its own `RWMutex`, we reduced lock contention and achieved an **8.3x performance boost** on multi-core systems.
- **Before Optimization**: ~705ns (16-core contention)
- **After Optimization**: **~84ns** (Sub-100ns access time)
- **Scalability**: Unlike standard map implementations that bottleneck as you add cores, this architecture scales linearly.

### 🧩 Custom DNS Engine
Built entirely without high-level DNS libraries, this project implements the full DNS protocol spec:
- **Zero-Dependency Parser**: High-efficiency binary parsing of DNS headers, questions, and resource records.
- **Smart Recursion**: Intelligent traversal from Root Servers to Authoritative nameservers with CNAME following and IPv6 fallback.
- **Protocol Agnostic**: Seamlessly handles UDP-to-TCP fallback for truncated responses.

### 🧵 Concurrency Model
Uses a highly concurrent "Goroutine-per-request" model, enabling the server to handle thousands of simultaneous queries with an internal processing overhead of only **~1 microsecond**.

---

## 📊 Performance at a Glance

| Metric | Performance |
| :--- | :--- |
| **Cache Hit Latency** | **~84 ns** (16-core parallel) |
| **End-to-End Processing** | **~1 µs** (Cache hit) |
| **Memory Allocation** | Optimized to ~320 B per request |
| **Scalability** | O(1) shard access with O(N) core scaling |

*For detailed benchmarks and memory profiles, see [PERFORMANCE.md](./PERFORMANCE.md).*

---

## ✨ Features

- **Recursive Resolution**: Full path traversal from Root to Authority.
- **UDP & TCP Support**: Robust handling of protocol switching.
- **EDNS0 Support**: Extension mechanisms for modern DNS features.
- **Negative Caching**: Caches SOA records for NXDOMAIN to prevent redundant upstream hits.
- **Configurable Sharding**: Fine-tune performance via `DNS_CACHE_SHARDS` environment variable.

## 🛠 Getting Started

### Prerequisites
- Go 1.22+
- Docker (optional)

### Quick Start
```bash
# Clone and Run
git clone https://github.com/rounakkumarsingh/dns-server-go.git
cd dns-server-go
go run .
```
*Server listens on `:1053` by default.*

## 🧪 Testing & Verification

The project includes a rigorous testing suite covering both functional correctness and performance stability.

```bash
# Run Functional Tests
go test -v ./...

# Run Scalability Benchmarks
go test -bench . -benchmem ./...
```

## 🐳 Deployment
Optimized for containerized environments. See [DEPLOYMENT.md](./DEPLOYMENT.md) for CI/CD and Cloud scaling strategies.

```bash
docker build -t dns-server .
docker run -p 1053:1053/udp dns-server
```

## 📜 License
MIT License.
