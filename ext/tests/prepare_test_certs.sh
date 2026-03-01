#!/bin/sh
set -eu

CERT_FILE=${QUIC_TEST_CERT:-/tmp/nghttp3-localhost.crt}
KEY_FILE=${QUIC_TEST_KEY:-/tmp/nghttp3-localhost.key}

openssl req -x509 -newkey rsa:2048 \
  -keyout "$KEY_FILE" \
  -out "$CERT_FILE" \
  -days 1 \
  -nodes \
  -subj "/CN=localhost"

printf 'cert=%s\nkey=%s\n' "$CERT_FILE" "$KEY_FILE"
