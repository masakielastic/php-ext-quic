--TEST--
Close semantics after established QUIC stream exchange
--SKIPIF--
<?php
require __DIR__ . '/integration_skipif.inc';
quic_integration_skipif([
    'require_env' => true,
    'require_certs' => true,
    'probe_bind' => true,
]);
?>
--FILE--
<?php
require __DIR__ . '/close_failure_integration.php';
?>
--EXPECT--
string(3) "ok
"
string(5) "ping
"
bool(true)
bool(false)
string(14) "Quic\Exception"
string(16) "Stream is closed"
NULL
NULL
NULL
bool(false)
NULL
bool(true)
bool(false)
string(14) "Quic\Exception"
string(16) "Stream is closed"
NULL
NULL
