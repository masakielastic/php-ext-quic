<?php

function driveExchange(
    Quic\ServerConnection $server,
    $serverStream,
    Quic\ClientConnection $client,
    $clientStream,
    string $request,
): array {
    $opened = false;
    $accepted = false;
    $responded = false;
    $serverRequest = '';
    $body = '';
    $serverSideStream = null;
    $clientSideStream = null;
    $deadline = microtime(true) + 5.0;

    $client->startHandshake();

    while (microtime(true) < $deadline) {
        $client->flush();
        $server->flush();

        if (!$accepted) {
            $candidate = $server->popAcceptedStream();
            if ($candidate instanceof Quic\Stream) {
                $serverSideStream = $candidate;
                $accepted = true;
            }
        }

        if ($client->isHandshakeComplete() && !$opened) {
            $clientSideStream = $client->openBidirectionalStream();
            $clientSideStream->write($request, true);
            $opened = true;
        }

        if ($accepted) {
            $chunk = $serverSideStream->read();
            if ($chunk !== '') {
                $serverRequest .= $chunk;
            }

            if (
                !$responded &&
                $serverSideStream->isFinished() &&
                $serverSideStream->isWritable()
            ) {
                $serverSideStream->write("server response: " . $serverRequest, true);
                $server->flush();
                $responded = true;
            }
        }

        if ($opened) {
            $chunk = $clientSideStream->read();
            if ($chunk !== '') {
                $body .= $chunk;
            }

            if ($responded && str_contains($body, "server response: " . $request)) {
                break;
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

    if (!$accepted || !$opened || $body !== "server response: " . $request) {
        throw new RuntimeException('exchange did not complete');
    }

    return [
        'client_handshake' => $client->isHandshakeComplete(),
        'accepted' => $accepted,
        'request' => $serverRequest,
        'response' => $body,
    ];
}

$server = new Quic\ServerConnection('127.0.0.1', 0, [
    'certfile' => '/tmp/nghttp3-localhost.crt',
    'keyfile' => '/tmp/nghttp3-localhost.key',
    'response' => null,
]);
$serverStream = $server->getStream();
$port = $server->getLocalAddress()['port'];

$client1 = new Quic\ClientConnection('127.0.0.1', $port, [
    'verify_peer' => false,
]);
$client1Stream = $client1->getStream();
$exchange1 = driveExchange($server, $serverStream, $client1, $client1Stream, "ping-1\n");

$client2 = new Quic\ClientConnection('127.0.0.1', $port, [
    'verify_peer' => false,
]);
$client2Stream = $client2->getStream();
$exchange2 = driveExchange($server, $serverStream, $client2, $client2Stream, "ping-2\n");

$peerAddress = $server->getPeerAddress();
$client2Local = $client2->getLocalAddress();

var_dump($exchange1['client_handshake']);
var_dump($exchange1['accepted']);
var_dump($exchange1['request']);
var_dump($exchange1['response']);
var_dump($exchange2['client_handshake']);
var_dump($exchange2['accepted']);
var_dump($exchange2['request']);
var_dump($exchange2['response']);
var_dump($server->isHandshakeComplete());
var_dump($peerAddress['port'] === $client2Local['port']);

fclose($client2Stream);
fclose($client1Stream);
fclose($serverStream);
$client2->close();
$client1->close();
$server->close();
