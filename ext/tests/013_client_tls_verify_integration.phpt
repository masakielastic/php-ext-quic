--TEST--
Quic\ClientConnection verifies server certificates with cafile and capath
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
require __DIR__ . '/client_tls_verify_integration.php';
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
string(7) "cafile
"
string(16) "verified cafile
"
bool(true)
bool(true)
bool(true)
string(7) "capath
"
string(16) "verified capath
"
