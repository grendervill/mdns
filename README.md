# mdns

Self-hosted DNS server in Go: plain DNS, DoH (h1/h2/h3), DoT and DoQ listeners,
upstream forwarding with caching, routing strategies, health checks and query
logging. Single static binary, runs as `mdns serve`.

## Quick start

    make build
    bin/mdns version
