--TEST--
Quic\Stream exposes peer STOP_SENDING via write-stop observation
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
require __DIR__ . '/stream_stop_sending_integration.php';
?>
--EXPECT--
bool(true)
NULL
bool(false)
bool(true)
