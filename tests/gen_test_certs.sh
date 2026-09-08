#!/usr/bin/env bash
# Generates throwaway TLS test material into $1: a self-signed CA and a server
# certificate (EC P-256) with SAN DNS:localhost. Run by the build for tls_test;
# the files are NOT committed. Regenerates only when missing.
set -eu

OUT="${1:?usage: gen_test_certs.sh <output-dir>}"
mkdir -p "$OUT"

if [ -f "$OUT/ca.crt" ] && [ -f "$OUT/srv.crt" ] && [ -f "$OUT/srv.key" ]; then
    exit 0
fi

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$OUT/ca.key" -out "$OUT/ca.crt" -days 3 -subj "/CN=taps-test-ca" \
    -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null

openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$OUT/srv.key" -out "$OUT/srv.csr" -subj "/CN=localhost" 2>/dev/null

openssl x509 -req -in "$OUT/srv.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" \
    -CAcreateserial -out "$OUT/srv.crt" -days 3 \
    -extfile <(printf "subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE") 2>/dev/null

rm -f "$OUT/srv.csr" "$OUT/ca.srl"
