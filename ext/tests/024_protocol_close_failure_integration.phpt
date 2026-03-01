--TEST--
Server-side connection close reaches the client as a protocol failure path
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
require __DIR__ . '/protocol_close_failure_integration.php';
?>
--EXPECT--
bool(true)
bool(true)
