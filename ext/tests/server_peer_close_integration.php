<?php

function pumpOnce(
    Quic\ServerConnection $server,
    $serverStream,
    ?Quic\ClientConnection $client,
    $clientStream,
): void {
    if ($client instanceof Quic\ClientConnection) {
        $client->flush();
    }
    $server->flush();

    $read = [$serverStream];
    if (is_resource($clientStream)) {
        $read[] = $clientStream;
    }
    $write = null;
    $except = null;
    $timeouts = array_values(array_filter([
        $server->getTimeout(),
        $client?->getTimeout(),
    ], static fn($value) => $value !== null));

    $timeout = $timeouts ? max(0, min(min($timeouts), 50)) : 50;
    $seconds = intdiv($timeout, 1000);
    $microseconds = ($timeout % 1000) * 1000;

    $ready = @stream_select($read, $write, $except, $seconds, $microseconds);
    if ($ready === false) {
        throw new RuntimeException('stream_select failed');
    }

    if ($ready === 0) {
        $server->handleExpiry();
        if ($client instanceof Quic\ClientConnection) {
            $client->handleExpiry();
        }
        return;
    }

    foreach ($read as $resource) {
        if ($resource === $serverStream) {
            $server->handleReadable();
        } elseif ($client instanceof Quic\ClientConnection && $resource === $clientStream) {
            $client->handleReadable();
        }
    }
}

function drainAfterPeerClose(
    Quic\ServerConnection $server,
    $serverStream,
    Quic\ClientConnection $client,
    $clientStream,
): void {
    $deadline = microtime(true) + 0.5;

    while (microtime(true) < $deadline) {
        try {
            pumpOnce($server, $serverStream, $client, $clientStream);
        } catch (Quic\ProtocolException $e) {
            if (
                !str_contains($e->getMessage(), 'ERR_DROP_CONN') &&
                !str_contains($e->getMessage(), 'ERR_DRAINING')
            ) {
                throw $e;
            }
        }
    }
}

function waitForAcceptedPeer(
    Quic\ServerConnection $server,
    $serverStream,
    Quic\ClientConnection $client,
    $clientStream,
): Quic\ServerPeer {
    $client->startHandshake();
    $peer = null;
    $deadline = microtime(true) + 5.0;

    while (microtime(true) < $deadline) {
        pumpOnce($server, $serverStream, $client, $clientStream);

        if (!$peer instanceof Quic\ServerPeer) {
            $candidate = $server->popAcceptedPeer();
            if ($candidate instanceof Quic\ServerPeer) {
                $peer = $candidate;
            }
        }

        if (
            $peer instanceof Quic\ServerPeer &&
            $peer->isHandshakeComplete() &&
            $client->isHandshakeComplete()
        ) {
            return $peer;
        }
    }

    throw new RuntimeException('peer was not accepted');
}

function exchangeRequest(
    Quic\ServerConnection $server,
    Quic\ServerPeer $peer,
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

    while (microtime(true) < $deadline) {
        pumpOnce($server, $serverStream, $client, $clientStream);

        if (!$accepted) {
            $candidate = $peer->popAcceptedStream();
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
                return [
                    'peer_handshake' => $peer->isHandshakeComplete(),
                    'request' => $serverRequest,
                    'response' => $body,
                ];
            }
        }
    }

    throw new RuntimeException('request exchange did not complete');
}

$server = new Quic\ServerConnection('127.0.0.1', 0, [
    'certfile' => '/tmp/nghttp3-localhost.crt',
    'keyfile' => '/tmp/nghttp3-localhost.key',
    'response' => null,
]);
$serverStream = $server->getPollStream();
$port = $server->getLocalAddress()['port'];

$client1 = new Quic\ClientConnection('127.0.0.1', $port, [
    'verify_peer' => false,
]);
$client1Stream = $client1->getPollStream();
$peer1 = waitForAcceptedPeer($server, $serverStream, $client1, $client1Stream);
$peer1Address = $peer1->getPeerAddress();
$client1Local = $client1->getLocalAddress();

$peer1->close();
$server->flush();
drainAfterPeerClose($server, $serverStream, $client1, $client1Stream);
fclose($client1Stream);
$client1->close();

$client2 = new Quic\ClientConnection('127.0.0.1', $port, [
    'verify_peer' => false,
]);
$client2Stream = $client2->getPollStream();
$peer2 = waitForAcceptedPeer($server, $serverStream, $client2, $client2Stream);
$peer2Address = $peer2->getPeerAddress();
$result = exchangeRequest($server, $peer2, $serverStream, $client2, $client2Stream, "ping-2\n");
$client2Local = $client2->getLocalAddress();
$serverPeerAddress = $server->getPeerAddress();

var_dump($peer1Address['port'] === $client1Local['port']);
var_dump($peer2->isHandshakeComplete());
var_dump($result['peer_handshake']);
var_dump($result['request']);
var_dump($result['response']);
var_dump($server->isHandshakeComplete());
var_dump($serverPeerAddress['port'] === $client2Local['port']);
var_dump($peer2Address['port'] === $client2Local['port']);

fclose($client2Stream);
fclose($serverStream);
$client2->close();
$server->close();
