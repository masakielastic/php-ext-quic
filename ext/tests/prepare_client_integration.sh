#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

SERVER_BIN=${QUIC_SAMPLE_SERVER_BIN:-/tmp/quic-sample-server}
CERT_FILE=${QUIC_SAMPLE_SERVER_CERT:-/tmp/nghttp3-localhost.crt}
KEY_FILE=${QUIC_SAMPLE_SERVER_KEY:-/tmp/nghttp3-localhost.key}

cc -O2 -o "$SERVER_BIN" "$REPO_DIR/sample_server.c" \
  -lngtcp2_crypto_gnutls -lngtcp2 -lgnutls

openssl req -x509 -newkey rsa:2048 \
  -keyout "$KEY_FILE" \
  -out "$CERT_FILE" \
  -days 1 \
  -nodes \
  -subj "/CN=localhost"

printf 'server=%s\ncert=%s\nkey=%s\n' "$SERVER_BIN" "$CERT_FILE" "$KEY_FILE"
