# AGENTS.md — RealiTLScanner

## Project Overview

RealiTLScanner is a Go CLI tool that scans IP addresses, CIDR ranges, and domains for TLS 1.3 + HTTP/2 (h2) endpoints. It identifies "feasible" targets (TLS 1.3, h2 ALPN, valid cert with domain and issuer) and writes results to CSV. Part of the XTLS ecosystem.

- **Module**: `github.com/xtls/RealiTLScanner`
- **Go version**: 1.21+
- **External dependency**: `github.com/oschwald/geoip2-golang` (optional GeoIP lookup via MaxMind `Country.mmdb`)

## Commands

```bash
# Build
go build -o RealiTLScanner .

# Run (requires at least one input source)
./RealiTLScanner -addr 1.2.3.4
./RealiTLScanner -in targets.txt
./RealiTLScanner -url https://example.com/mirrors

# Docker build & run
docker build -t realitlscanner .
docker run --rm realitlscanner -addr 1.1.1.1

# Tidy dependencies
go mod tidy
```

There is no test suite, Makefile, CI config, or lint configuration in this repository.

## Code Organization

All source lives at the repository root in `package main`:

| File | Purpose |
|------|---------|
| `main.go` | CLI flag parsing, input source routing, worker pool orchestration |
| `scanner.go` | `ScanTLS()` — dials a host, performs TLS handshake, checks feasibility, writes results |
| `utils.go` | `Host` type, `HostType` enum, input iteration (`Iterate`, `IterateAddr`), IP utilities, output writer |
| `geo.go` | `Geo` type — wraps `geoip2` reader with mutex-protected country lookups |
| `Dockerfile` | Multi-stage build (Go 1.22-alpine → alpine) |

## Key Types and Globals

- **`Host` struct** (`utils.go:26`): `IP net.IP`, `Origin string`, `Type HostType`
- **`HostType` enum** (`utils.go:17-22`): `HostTypeIP` (1), `HostTypeCIDR` (2), `HostTypeDomain` (3)
- **`Geo` struct** (`geo.go:10`): holds `*geoip2.Reader` and `sync.Mutex`
- **Package-level globals** (`main.go:15-23`): `addr`, `in`, `port`, `thread`, `out`, `timeout`, `verbose`, `enableIPv6`, `url` — set by `flag.Parse()`, read by other files

## Conventions and Patterns

- **Single package**: Everything is in `package main` — no sub-packages.
- **Logging**: Uses `log/slog` with structured key-value pairs. Verbose mode sets level to `Debug`; default is `Info`.
- **Concurrency**: Worker pool pattern with `sync.WaitGroup`. `hostChan` is a read-only channel (`<-chan Host`) producing hosts; each worker calls `ScanTLS()`. Output is written through a single goroutine via `OutWriter()`.
- **Feasibility check** (`scanner.go:54`): A target is "feasible" only if TLS version is 1.3 **and** ALPN is "h2" **and** cert has a non-empty CommonName **and** cert has a non-empty Issuer Organization.
- **Infinite scan mode** (`IterateAddr` in `utils.go:114`): When `-addr` is a single IP or resolved domain, the scanner expands outward from that IP in both directions indefinitely (up to `math.MaxInt`).
- **Proxy unset**: `main.go:26-29` explicitly unsets `ALL_PROXY`, `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` env vars at startup.
- **CSV output format**: `IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER,GEO_CODE` (issuer is double-quoted).
- **GeoIP is optional**: If `Country.mmdb` is not present in the working directory, GeoIP returns "N/A" with a warning.

## Gotchas

- **No tests exist.** There is no test file, test framework, or CI pipeline. If adding tests, you will need to create them from scratch.
- **Package-level globals** (`port`, `timeout`, `enableIPv6`) in `main.go` are read by `scanner.go` and `utils.go` without explicit passing. This is intentional but means these files are tightly coupled to `main.go`.
- **`NextIP`** (`utils.go:195`) modifies IP as `big.Int` bytes — for IPv4 the result is a 16-byte slice (Go's `net.IP` internal representation), not a 4-byte slice.
- **TLS `InsecureSkipVerify: true`** (`scanner.go:34`): The scanner intentionally skips certificate verification to extract cert info regardless of validity.
- **`LookupIP`** (`utils.go:159`) returns only the first resolved IP (prefers IPv4 unless `-46` flag is set).
- **CIDR iteration** in `Iterate` expands all IPs in a CIDR into memory via the channel — large CIDRs (e.g., /8) will generate massive output.
- **`Country.mmdb`** is gitignored — it must be manually placed in the working directory.
