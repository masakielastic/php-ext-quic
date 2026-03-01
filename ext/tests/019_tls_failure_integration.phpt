--TEST--
QUIC TLS failure paths surface predictable exceptions
--SKIPIF--
<?php
if (!extension_loaded('quic')) {
    echo 'skip extension not loaded';
    return;
}
if (!is_file('/tmp/nghttp3-localhost.crt') || !is_file('/tmp/nghttp3-localhost.key')) {
    echo 'skip prepare /tmp/nghttp3-localhost.crt and /tmp/nghttp3-localhost.key first';
}
?>
--FILE--
<?php
require __DIR__ . '/tls_failure_integration.php';
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
