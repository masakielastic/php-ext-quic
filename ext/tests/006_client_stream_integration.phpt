--TEST--
Quic\ClientConnection exchanges stream data with the PHP server example
--SKIPIF--
<?php
require __DIR__ . '/integration_skipif.inc';
quic_integration_skipif([
    'require_env' => true,
    'require_certs' => true,
    'require_proc_open' => true,
    'probe_child_bind' => true,
]);
?>
--FILE--
<?php
require __DIR__ . '/client_stream_integration.php';
?>
--EXPECT--
bool(true)
bool(true)
string(20) "integration response"
string(4) "ping"
