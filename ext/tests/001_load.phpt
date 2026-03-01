--TEST--
quic extension loads and registers core classes
--SKIPIF--
<?php
if (!extension_loaded('quic')) {
    echo 'skip extension not loaded';
}
?>
--FILE--
<?php
var_dump(extension_loaded('quic'));
var_dump(class_exists(Quic\ClientConnection::class));
var_dump(class_exists(Quic\ServerConnection::class));
var_dump(class_exists(Quic\Stream::class));
var_dump(class_exists(Quic\Exception::class));
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
