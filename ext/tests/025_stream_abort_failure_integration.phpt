--TEST--
Peer-reset stream enters an abort failure path for further writes
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
require __DIR__ . '/stream_abort_failure_integration.php';
?>
--EXPECT--
bool(true)
int(55)
bool(true)
bool(false)
bool(true)
bool(true)
bool(true)
bool(true)
