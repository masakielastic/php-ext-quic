--TEST--
Quic\ServerPeer close leaves the listener able to accept a new peer
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
require __DIR__ . '/server_peer_close_integration.php';
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
string(7) "ping-2
"
string(24) "server response: ping-2
"
bool(true)
