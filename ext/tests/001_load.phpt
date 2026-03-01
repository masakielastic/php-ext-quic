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
var_dump(class_exists(Quic\ServerPeer::class));
var_dump(class_exists(Quic\Stream::class));
var_dump(class_exists(Quic\Exception::class));
var_dump(method_exists(Quic\ClientConnection::class, 'getPollStream'));
var_dump(method_exists(Quic\ServerConnection::class, 'getPollStream'));
var_dump(method_exists(Quic\ClientConnection::class, 'getStream'));
var_dump(method_exists(Quic\ServerConnection::class, 'getStream'));
var_dump(method_exists(Quic\ServerConnection::class, 'isHandshakeComplete'));
var_dump(method_exists(Quic\ServerConnection::class, 'popAcceptedStream'));
var_dump(method_exists(Quic\ServerConnection::class, 'getPeerAddress'));
var_dump(method_exists(Quic\Stream::class, 'reset'));
var_dump(method_exists(Quic\Stream::class, 'stop'));
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(false)
bool(false)
bool(false)
bool(false)
bool(false)
bool(true)
bool(true)
