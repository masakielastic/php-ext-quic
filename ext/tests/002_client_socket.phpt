--TEST--
Quic\ClientConnection creates a UDP socket stream and exposes addresses
--SKIPIF--
<?php
if (!extension_loaded('quic')) {
    echo 'skip extension not loaded';
}
?>
--FILE--
<?php
$client = new Quic\ClientConnection('127.0.0.1', 4433);
$stream = $client->getPollStream();
$peer = $client->getPeerAddress();
$local = $client->getLocalAddress();

var_dump(is_resource($stream));
var_dump(get_resource_type($stream));
var_dump($peer['family']);
var_dump($peer['address']);
var_dump($peer['port']);
var_dump($local['family']);
var_dump($local['address']);
var_dump(is_int($local['port']));
var_dump($local['port'] > 0);

$client->close();

try {
    $client->getPollStream();
} catch (Quic\Exception $e) {
    echo $e->getMessage(), PHP_EOL;
}
?>
--EXPECTF--
bool(true)
string(%d) "stream"
string(7) "AF_INET"
string(9) "127.0.0.1"
int(4433)
string(7) "AF_INET"
string(9) "127.0.0.1"
bool(true)
bool(true)
Connection is closed
