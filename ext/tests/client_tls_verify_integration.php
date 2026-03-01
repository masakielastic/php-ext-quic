<?php

function pumpVerifiedOnce(
    Quic\ServerConnection $server,
    $serverStream,
    Quic\ClientConnection $client,
    $clientStream
): void {
    $client->flush();
    $server->flush();

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
        return;
    }

    foreach ($read as $resource) {
        if ($resource === $serverStream) {
            $server->handleReadable();
        } elseif ($resource === $clientStream) {
            $client->handleReadable();
        }
    }
}

function drainVerifiedClose(
    Quic\ServerConnection $server,
    $serverStream,
    Quic\ClientConnection $client,
    $clientStream
): void {
    $deadline = microtime(true) + 0.5;

    while (microtime(true) < $deadline) {
        try {
            pumpVerifiedOnce($server, $serverStream, $client, $clientStream);
        } catch (Quic\ProtocolException $e) {
            if (
                !str_contains($e->getMessage(), 'ERR_CLOSING') &&
                !str_contains($e->getMessage(), 'ERR_DRAINING') &&
                !str_contains($e->getMessage(), 'ERR_DROP_CONN')
            ) {
                throw $e;
            }
        }
    }
}

function driveVerifiedExchange(
    Quic\ServerConnection $server,
    $serverStream,
    array $clientOptions,
    string $request,
    string $response
): array {
    $client = new Quic\ClientConnection(
        '127.0.0.1',
        $server->getLocalAddress()['port'],
        $clientOptions,
    );
    $clientStream = $client->getPollStream();
    $acceptedPeer = null;
    $accepted = false;
    $opened = false;
    $responded = false;
    $serverRequest = '';
    $body = '';
    $serverSideStream = null;
    $clientSideStream = null;
    $deadline = microtime(true) + 5.0;

    stream_set_blocking($clientStream, false);
    $client->startHandshake();

    try {
        while (microtime(true) < $deadline) {
            if (!$acceptedPeer instanceof Quic\ServerPeer) {
                $candidate = $server->popAcceptedPeer();
                if ($candidate instanceof Quic\ServerPeer) {
                    $acceptedPeer = $candidate;
                }
            }

            if (!$accepted) {
                $candidate = $acceptedPeer?->popAcceptedStream();
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
                    $serverSideStream->write($response, true);
                    $server->flush();
                    $responded = true;
                }
            }

            if ($opened) {
                $chunk = $clientSideStream->read();
                if ($chunk !== '') {
                    $body .= $chunk;
                }

                if ($responded && str_contains($body, $response)) {
                    break;
                }
            }

            pumpVerifiedOnce($server, $serverStream, $client, $clientStream);
        }

        if (!$accepted || !$opened || $body !== $response) {
            throw new RuntimeException('verified exchange did not complete');
        }

        $peerHandshake = $acceptedPeer?->isHandshakeComplete() ?? false;

        if ($acceptedPeer instanceof Quic\ServerPeer) {
            $acceptedPeer->close();
            $server->flush();
            drainVerifiedClose($server, $serverStream, $client, $clientStream);
        }

        return [
            'client_handshake' => $client->isHandshakeComplete(),
            'peer_handshake' => $peerHandshake,
            'accepted' => $accepted,
            'request' => $serverRequest,
            'response' => $body,
        ];
    } finally {
        fclose($clientStream);
        $client->close();
    }
}

$cert = '/tmp/nghttp3-localhost.crt';
$key = '/tmp/nghttp3-localhost.key';
$capath = sys_get_temp_dir() . '/quic-capath-' . bin2hex(random_bytes(4));

if (!mkdir($capath, 0700)) {
    throw new RuntimeException('failed to create capath');
}

if (!copy($cert, $capath . '/localhost.crt')) {
    rmdir($capath);
    throw new RuntimeException('failed to populate capath');
}

$server = new Quic\ServerConnection('127.0.0.1', 0, [
    'certfile' => $cert,
    'keyfile' => $key,
    'response' => null,
]);
$serverStream = $server->getPollStream();
stream_set_blocking($serverStream, false);

try {
    $cafileExchange = driveVerifiedExchange(
        $server,
        $serverStream,
        [
            'verify_peer' => true,
            'cafile' => $cert,
            'server_name' => 'localhost',
        ],
        "cafile\n",
        "verified cafile\n",
    );

    $capathExchange = driveVerifiedExchange(
        $server,
        $serverStream,
        [
            'verify_peer' => true,
            'capath' => $capath,
            'server_name' => 'localhost',
        ],
        "capath\n",
        "verified capath\n",
    );

    var_dump($cafileExchange['client_handshake']);
    var_dump($cafileExchange['peer_handshake']);
    var_dump($cafileExchange['accepted']);
    var_dump($cafileExchange['request']);
    var_dump($cafileExchange['response']);
    var_dump($capathExchange['client_handshake']);
    var_dump($capathExchange['peer_handshake']);
    var_dump($capathExchange['accepted']);
    var_dump($capathExchange['request']);
    var_dump($capathExchange['response']);
} finally {
    fclose($serverStream);
    $server->close();
    unlink($capath . '/localhost.crt');
    rmdir($capath);
}
