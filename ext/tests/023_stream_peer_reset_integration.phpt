--TEST--
Quic\Stream exposes peer reset reason and final size
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
require __DIR__ . '/stream_peer_reset_integration.php';
?>
--EXPECT--
bool(true)
int(42)
int(0)
bool(true)
int(9)
int(0)
