--TEST--
Quic\ClientConnection rejects opening a stream before handshake completion
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

try {
    $client->openBidirectionalStream();
} catch (Quic\Exception $e) {
    echo $e->getMessage(), PHP_EOL;
}
?>
--EXPECT--
Handshake is not complete
