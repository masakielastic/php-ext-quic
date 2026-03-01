--TEST--
Quic\ServerConnection and Quic\ClientConnection complete a handshake and exchange stream data
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
require __DIR__ . '/server_client_integration.php';
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
string(5) "ping
"
string(16) "server response
"
