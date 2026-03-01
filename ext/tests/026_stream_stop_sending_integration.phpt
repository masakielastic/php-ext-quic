--TEST--
Quic\Stream exposes peer STOP_SENDING via write-stop observation
--SKIPIF--
<?php
if (!extension_loaded('quic')) {
    echo "skip extension not loaded";
    return;
}
if (!is_file('/tmp/nghttp3-localhost.crt') || !is_file('/tmp/nghttp3-localhost.key')) {
    echo 'skip prepare /tmp/nghttp3-localhost.crt and /tmp/nghttp3-localhost.key first';
    return;
}
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
