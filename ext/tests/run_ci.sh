#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
EXT_DIR=$REPO_DIR/ext
EXTENSION=$EXT_DIR/modules/quic.so

JOBS=${JOBS:-4}

sh "$SCRIPT_DIR/prepare_test_certs.sh"

cd "$EXT_DIR"
phpize
./configure --enable-quic
make -j"$JOBS"

make test TESTS='tests/001_load.phpt' REPORT_EXIT_STATUS=1 NO_INTERACTION=1

php -d "extension=$EXTENSION" "$SCRIPT_DIR/server_client_integration.php"
php -d "extension=$EXTENSION" "$SCRIPT_DIR/server_multi_client_integration.php"
php -d "extension=$EXTENSION" "$SCRIPT_DIR/server_peer_close_integration.php"
php -d "extension=$EXTENSION" "$SCRIPT_DIR/server_stream_queue_order_integration.php"
php -d "extension=$EXTENSION" "$SCRIPT_DIR/client_tls_verify_integration.php"
php -d "extension=$EXTENSION" "$SCRIPT_DIR/tls_failure_integration.php"
php -d "extension=$EXTENSION" "$SCRIPT_DIR/stream_reset_stop_integration.php"
php -d "extension=$EXTENSION" "$SCRIPT_DIR/close_failure_integration.php"
php -d "extension=$EXTENSION" "$SCRIPT_DIR/stream_peer_reset_integration.php"
php -d "extension=$EXTENSION" "$SCRIPT_DIR/protocol_close_failure_integration.php"
php -d "extension=$EXTENSION" "$SCRIPT_DIR/stream_abort_failure_integration.php"
php -d "extension=$EXTENSION" "$SCRIPT_DIR/stream_stop_sending_integration.php"
