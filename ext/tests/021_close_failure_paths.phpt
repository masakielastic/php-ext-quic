--TEST--
Close semantics for client and server connection objects
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
$client->close();

foreach ([
    static fn() => $client->getPollStream(),
    static fn() => $client->startHandshake(),
    static fn() => $client->flush(),
    static fn() => $client->handleReadable(),
    static fn() => $client->handleExpiry(),
    static fn() => $client->openBidirectionalStream(),
] as $case) {
    try {
        $case();
        echo "no-error\n";
    } catch (Throwable $e) {
        echo get_class($e), PHP_EOL;
        echo $e->getMessage(), PHP_EOL;
    }
}

var_dump($client->getTimeout());

$server = new Quic\ServerConnection('127.0.0.1', 0, [
    'certfile' => '/tmp/nghttp3-localhost.crt',
    'keyfile' => '/tmp/nghttp3-localhost.key',
    'response' => null,
]);
$server->close();

foreach ([
    static fn() => $server->getPollStream(),
    static fn() => $server->handleReadable(),
    static fn() => $server->accept(),
] as $case) {
    try {
        $case();
        echo "no-error\n";
    } catch (Throwable $e) {
        echo get_class($e), PHP_EOL;
        echo $e->getMessage(), PHP_EOL;
    }
}

var_dump($server->getTimeout());
var_dump($server->popAcceptedPeer());
?>
--EXPECT--
Quic\Exception
Connection is closed
Quic\Exception
Connection is closed
Quic\Exception
Handshake has not been started
Quic\Exception
Handshake has not been started
Quic\Exception
Handshake has not been started
Quic\Exception
Handshake has not been started
NULL
Quic\Exception
Socket is closed
Quic\Exception
Socket is closed
Quic\Exception
Socket is closed
NULL
NULL
