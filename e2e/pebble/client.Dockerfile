# Client image for the pebble e2e: the tools the checks need (dig,
# kdig for DoT/DoQ, openssl for the certificate inspection, curl for the
# pebble root and §RFC 8484 DoH).
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq \
 && apt-get install -y -qq dnsutils knot-dnsutils openssl curl ca-certificates >/dev/null \
 && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
