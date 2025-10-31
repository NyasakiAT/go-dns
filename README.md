# Go DNS Forwarder

A lightweight DNS forwarder written in Go.  
It listens for DNS queries, forwards them to an upstream resolver (e.g. `9.9.9.9`), and sends the responses back to the client.

Designed for learning how DNS works at the packet level — parsing headers, handling compression pointers, and building real network logic from scratch.

---

## 🚀 Features

- [x] Parses and builds DNS headers manually (bit-fields, flags, etc.)
- [x] Handles domain name compression (`0xC0` pointer format)
- [x] Forwards queries to upstream servers (`9.9.9.9:53`)
- [x] Non-blocking UDP handling using goroutines
- [x] Simple logging for requests and responses

---

## 🧭 Planned / TODO

### 🧠 Caching Layer
**Goal:** reduce upstream lookups and improve response speed.

- [ ] Implement an in-memory cache using `sync.Map` or LRU.
- [ ] Cache key: `(QNAME, QTYPE, QCLASS, DO-bit)`.
- [ ] Respect DNS TTLs: store expiry timestamp and auto-expire entries.
- [ ] Rewrite transaction ID when serving cached responses.
- [ ] Add optional persistent cache (Ideally redis?)

### 🚫 Blocklists / Sinkhole
**Goal:** block unwanted or malicious domains.

- [ ] Load a list of domains from file or URL (`blocklist.txt`).
- [ ] Match on full domain or suffix (e.g. `ads.google.com`, `*.tracking.net`).
- [ ] Return a synthetic A record (`0.0.0.0`) or NXDOMAIN instead of forwarding.
- [ ] Cache blocked responses with infinite TTL.

### 🌍 GeoIP Lookup
**Goal:** log or route queries based on the client’s location.

- [ ] Integrate [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) using [`oschwald/geoip2-golang`](https://pkg.go.dev/github.com/oschwald/geoip2-golang).
- [ ] Log query source country / city.
- [ ] Maintain a metrics log for per-country query counts.

### 🏠 Local Overrides / Hosts File
**Goal:** define custom static records for specific domains.

- [ ] Load mappings from a simple `hosts.json` or `/etc/hosts` style file:
  ```json
  {
    "my.local.dev": "192.168.1.50",
    "printer.lan": "192.168.1.200"
  }
  ```
- [ ] When a matching QNAME is found, bypass upstream and reply locally.
- [ ] Cache local overrides as permanent records.

### ⚙️ Misc Enhancements

- [ ] Support multiple upstream resolvers with round-robin or fallback logic.
- [ ] Return `SERVFAIL` when upstream times out.
- [ ] Implement `EDNS(0)` and support larger UDP payloads.
- [ ] Graceful shutdown and metrics summary on exit.
- [ ] Command-line flags:
  - `--listen :8053`
  - `--upstream 9.9.9.9:53,1.1.1.1:53`
  - `--cache-ttl 300s`
  - `--geoip-db ./GeoLite2-City.mmdb`

---

## 🧩 Example Output

```
REQ:  ping.archlinux.org
REQ:  {13722 false 0 false false true false 0 0 1 0 0 0}
REQ:  ping.archlinux.org
ANS:  {49285 true 0 false false true true 0 0 1 2 0 0}
ANS:  ping.archlinux.org
```

---

## 📜 License

MIT — free to study, hack, and extend.
