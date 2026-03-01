<?php

// This script intentionally exercises the listener-level compatibility path.
// New code should prefer popAcceptedPeer() + ServerPeer::popAcceptedStream().

$server = new Quic\ServerConnection('127.0.0.1', 0, [
    'certfile' => '/tmp/nghttp3-localhost.crt',
    'keyfile' => '/tmp/nghttp3-localhost.key',
    'response' => null,
]);

$client = new Quic\ClientConnection('127.0.0.1', $server->getLocalAddress()['port'], [
    'verify_peer' => false,
]);

$serverStream = $server->getPollStream();
$clientStream = $client->getPollStream();
$client->startHandshake();

$opened = false;
$accepted = false;
$serverRequest = '';
$body = '';
$deadline = microtime(true) + 5.0;

while (microtime(true) < $deadline) {
    $client->flush();
    $server->flush();

    if (!$accepted) {
        $serverSideStream = $server->popAcceptedStream();
        if ($serverSideStream instanceof Quic\Stream) {
            $accepted = true;
        }
    }

    if ($client->isHandshakeComplete() && !$opened) {
        $stream = $client->openBidirectionalStream();
        $stream->write("compat\n", true);
        $opened = true;
    }

    if ($accepted) {
        $chunk = $serverSideStream->read();
        if ($chunk !== '') {
            $serverRequest .= $chunk;
        }

        if ($serverSideStream->isFinished() && $serverSideStream->isWritable()) {
            $serverSideStream->write("compat response\n", true);
            $server->flush();
        }
    }

    if ($opened) {
        $chunk = $stream->read();
        if ($chunk !== '') {
            $body .= $chunk;
            if (str_contains($body, "compat response\n")) {
                break;
            }
        }
    }

    $read = [$serverStream, $clientStream];
    $write = null;
    $except = null;
    $timeouts = array_values(array_filter([
        $server->getTimeout(),
        $client->getTimeout(),
    ], static fn($value) => $value !== null));

    $timeout = $timeouts ? max(0, min($timeouts)) : 50;
    $seconds = intdiv($timeout, 1000);
    $microseconds = ($timeout % 1000) * 1000;

    $ready = @stream_select($read, $write, $except, $seconds, $microseconds);
    if ($ready === false) {
        throw new RuntimeException('stream_select failed');
    }

    if ($ready === 0) {
        $server->handleExpiry();
        $client->handleExpiry();
        continue;
    }

    foreach ($read as $resource) {
        if ($resource === $serverStream) {
            $server->handleReadable();
        } elseif ($resource === $clientStream) {
            $client->handleReadable();
        }
    }
}

$serverPeerAddress = $server->getPeerAddress();
$clientLocal = $client->getLocalAddress();

var_dump($server->isHandshakeComplete());
var_dump($client->isHandshakeComplete());
var_dump($accepted);
var_dump($opened);
var_dump($serverPeerAddress['port'] === $clientLocal['port']);
var_dump($serverRequest);
var_dump($body);

fclose($serverStream);
fclose($clientStream);
$server->close();
$client->close();
