--TEST--
Quic\ClientConnection bootstraps GnuTLS and ngtcp2 state for handshake
--SKIPIF--
<?php
if (!extension_loaded('quic')) {
    echo 'skip extension not loaded';
}
?>
--FILE--
<?php
$client = new Quic\ClientConnection('127.0.0.1', 4433, [
    'verify_peer' => false,
    'alpn' => 'hq-interop',
]);

var_dump($client->getTimeout());

$client->startHandshake();
var_dump(is_int($client->getTimeout()));
var_dump($client->getTimeout() >= 0);
var_dump($client->isHandshakeComplete());

$client->flush();
echo "flushed\n";

try {
    $client->startHandshake();
} catch (Quic\Exception $e) {
    echo $e->getMessage(), PHP_EOL;
}
?>
--EXPECT--
NULL
bool(true)
bool(true)
bool(false)
flushed
Handshake has already been started
