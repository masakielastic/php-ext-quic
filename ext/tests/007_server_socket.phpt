--TEST--
Quic\ServerConnection binds a UDP socket stream and exposes its local address
--SKIPIF--
<?php
if (!extension_loaded('quic')) {
    echo 'skip extension not loaded';
}
?>
--FILE--
<?php
$server = new Quic\ServerConnection('127.0.0.1', 0);
$stream = $server->getStream();
$local = $server->getLocalAddress();
$peer = $server->getPeerAddress();

var_dump(is_resource($stream));
var_dump($local['family']);
var_dump($local['address']);
var_dump($local['port'] > 0);
var_dump($peer);

fclose($stream);
$server->close();
?>
--EXPECT--
bool(true)
string(7) "AF_INET"
string(9) "127.0.0.1"
bool(true)
array(0) {
}
