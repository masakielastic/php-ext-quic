--TEST--
Quic\Stream exposes peer reset reason and final size
--SKIPIF--
<?php
if (!extension_loaded('quic')) {
    echo 'skip extension not loaded';
    return;
}
if (!is_file('/tmp/nghttp3-localhost.crt') || !is_file('/tmp/nghttp3-localhost.key')) {
    echo 'skip prepare /tmp/nghttp3-localhost.crt and /tmp/nghttp3-localhost.key first';
    return;
}
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
