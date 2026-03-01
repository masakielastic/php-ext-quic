--TEST--
Quic\ClientConnection loop primitives work after handshake bootstrap
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
]);

$client->startHandshake();
$client->flush();
$client->handleExpiry();

try {
    $client->handleReadable();
} catch (Quic\Exception $e) {
    echo $e->getMessage(), PHP_EOL;
}

echo "expiry-ok\n";
?>
--EXPECT--
recvmsg() failed: Connection refused
expiry-ok
