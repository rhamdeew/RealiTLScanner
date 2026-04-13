# Codebase Analysis Report — RealiTLScanner

**Date**: 2026-04-13  
**Go version**: 1.25.3 (upgraded from 1.21)  
**Dependencies upgraded**: `geoip2-golang` v1.9.0 → v1.13.0, `maxminddb-golang` v1.12.0 → v1.13.0, `x/sys` v0.17.0 → v0.20.0

---

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 2     |
| MEDIUM   | 11    |
| LOW      | 7     |

---

## HIGH Severity

### 1. Panic on Empty PeerCertificates — `scanner.go:49`

```go
domain := state.PeerCertificates[0].Subject.CommonName
```

`state.PeerCertificates[0]` is accessed without checking if the slice is empty. If a TLS handshake succeeds but the peer presents no certificates, this panics with an index-out-of-range error.

**Fix**: Add a length check before access:
```go
if len(state.PeerCertificates) == 0 {
    slog.Debug("No peer certificates", "target", hostPort)
    return
}
```

---

### 2. NextIP Wraps Around at IP Boundaries — `utils.go:195-207`

When decrementing below `0.0.0.0`, `big.Int.Sub` produces a negative number. `big.Int.Bytes()` returns the absolute value, so `-1` becomes `+1` — meaning `NextIP(0.0.0.0, false)` incorrectly returns `0.0.0.1`. Similarly, incrementing past `255.255.255.255` silently produces wrong results. The padding logic `make([]byte, len(ip)-len(b))` can also panic if `len(b) > len(ip)` on overflow.

**Fix**: Check for boundary conditions:
```go
if !increment && ipb.Sign() == 0 {
    return nil
}
```
And in the caller (`IterateAddr`), check for `nil` and terminate the loop.

---

## MEDIUM Severity

### 3. TLS Connection Never Closed — `scanner.go:41`

The TLS client `c` is created via `tls.Client(conn, tlsCfg)` and handshaked, but `c.Close()` is never called. Only the underlying `conn.Close()` is deferred. The TLS close_notify alert is never sent, and internal TLS buffers may not be released.

**Fix**: After successful handshake, defer `c.Close()` (which also closes the underlying conn).

---

### 4. CSV Injection & Malformed Output — `scanner.go:59`

CSV output is assembled via string concatenation without proper escaping:
- Values like `domain` and `host.Origin` are not quoted — if they contain commas/newlines, the CSV breaks.
- If values start with `=`, `+`, `-`, or `@`, spreadsheet programs interpret them as formulas (CSV injection).
- `issuers` is manually wrapped in quotes, but internal quotes are not escaped to `""` per RFC 4180.

**Fix**: Use `encoding/csv`:
```go
w := csv.NewWriter(writer)
w.Write([]string{host.IP.String(), host.Origin, domain, issuers, geoCode})
w.Flush()
```

---

### 5. Unbounded `io.ReadAll` — Memory Exhaustion — `main.go:86`

```go
v, err := io.ReadAll(resp.Body)
```

Reads the entire HTTP response into memory with no size limit. A malicious URL could serve a multi-GB response.

**Fix**: Use `io.LimitReader`:
```go
v, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
```

---

### 6. `http.Get` with No Timeout — `main.go:80`

Uses the default HTTP client with no timeout. The request can hang indefinitely. The `timeout` flag is only used for TLS connections, not for this HTTP fetch.

**Fix**: Create a client with timeout:
```go
client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
resp, err := client.Get(url)
```

---

### 7. Unnecessary Mutex Serializes GeoIP Lookups — `geo.go:33-34`

`geoip2.Reader.Country()` wraps `maxminddb.Reader.Lookup()`, which is documented as safe for concurrent use. The `sync.Mutex` serializes all GeoIP lookups across all threads, creating a global contention point that defeats multi-threaded scanning.

**Fix**: Remove the mutex entirely:
```go
func (o *Geo) GetGeo(ip net.IP) string {
    if o.geoReader == nil {
        return "N/A"
    }
    country, err := o.geoReader.Country(ip)
    ...
}
```

---

### 8. Infinite Mode — No Graceful Shutdown — `utils.go:130-156`

When `-addr` is a single IP, `IterateAddr` enters "infinite mode" with an unbounded loop. The channel is never closed, so `wg.Wait()` never returns. Deferred cleanup (file close, channel close) never runs. The program can only be stopped by SIGKILL.

**Fix**: Add OS signal handling:
```go
ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
defer cancel()
```
Pass `ctx` to `IterateAddr` and check `ctx.Done()` in the loop.

---

### 9. No Input Validation on `port` Flag — `main.go:33`

`port` could be 0, negative, or >65535, producing invalid addresses from `net.JoinHostPort`.

**Fix**: Validate after flag parsing:
```go
if port < 1 || port > 65535 {
    slog.Error("Port must be between 1 and 65535")
    return
}
```

---

### 10. No Validation on `thread` Flag — `main.go:34`

`-thread 0` causes the program to exit immediately without scanning. `-thread` with a negative value causes `wg.Add` to panic.

**Fix**: Validate `thread >= 1` after parsing.

---

### 11. Write Errors Silently Ignored — `utils.go:190`

```go
_, _ = io.WriteString(writer, s)
```

If the output file runs out of disk space or encounters a write error, the program silently continues without reporting data loss.

**Fix**: Log the error:
```go
if _, err := io.WriteString(writer, s); err != nil {
    slog.Error("Write error", "err", err)
}
```

---

### 12. `InsecureSkipVerify: true` — `scanner.go:34`

TLS certificate verification is disabled. While this is intentional for a scanner that enumerates certificates, it means the tool is vulnerable to MITM if ever used in a trust-validation context.

**Recommendation**: Document the risk. If trust validation is ever needed, make this configurable.

---

### 13. No Validation on `timeout` Flag — `main.go:36`

A `timeout` of 0 would make all dials timeout immediately. A negative value would cause undefined behavior with `time.Duration`.

**Fix**: Validate `timeout >= 1` after parsing.

---

## LOW Severity

### 14. Regex Recompiled on Every Call — `utils.go:98`

`regexp.MustCompile(...)` inside `ValidateDomainName()` recompiles the regex on every invocation. For large input files, this happens thousands of times.

**Fix**: Promote to package-level variable:
```go
var domainRegex = regexp.MustCompile(`^[A-Za-z0-9\-.]+$`)
```

---

### 15. Regex Recompiled at Runtime — `main.go:91`

Same issue as above for the URL-parsing regex in `main.go`.

---

### 16. GeoIP Reader Never Closed — `geo.go:19`

`geoip2.Open()` returns a `*geoip2.Reader` with a `Close()` method that is never called. Low severity since the OS reclaims file descriptors on process exit, but poor practice.

**Fix**: Add a `Close()` method to `Geo` and defer it in `main`.

---

### 17. CSV Header Write Error Ignored — `main.go:64`

```go
_, _ = f.WriteString("IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER,GEO_CODE\n")
```

Error from writing the CSV header is silently discarded.

---

### 18. Hardcoded GeoIP Database Path — `geo.go:19`

`"Country.mmdb"` is hardcoded as a relative path. Running from a different working directory causes the file to not be found, silently degrading to "N/A" geo codes.

**Fix**: Make configurable via a flag or look in the executable's directory.

---

### 19. Domain Validation Regex Too Permissive — `utils.go:98`

The regex `^[A-Za-z0-9\-.]+$` allows strings like `-`, `..`, `---.`, which are not valid domain names. Invalid strings pass through and cause DNS lookup failures downstream.

---

### 20. Unnecessary String↔IP Round-Trip in Hot Loop — `utils.go:68`

Inside CIDR iteration, each `netip.Addr` is converted to string and back to `net.IP` via `net.ParseIP(addr.String())`. For large CIDRs this happens millions of times.

**Fix**: Convert directly:
```go
ip = net.IP(addr.AsSlice())
```

---

## Changes Already Applied

- `go.mod` updated from `go 1.21` to `go 1.25.3`
- `toolchain` directive removed (matched `go` directive)
- Dependencies upgraded to latest compatible versions
- Dockerfile still uses `golang:1.22-alpine` — consider updating to `golang:1.25-alpine` when available
