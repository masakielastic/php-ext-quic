<?php

declare(strict_types=1);

require __DIR__ . '/fiber_scheduler.php';

if ($argc < 3) {
    fwrite(STDERR, "Usage: php server_fiber_loop.php <port> <certfile> <keyfile> [response]\n");
    exit(1);
}

quic_require_fiber_support();

$port = (int) $argv[1];
$certfile = $argv[2];
$keyfile = $argv[3] ?? '';
$response = $argv[4] ?? "server response\n";

if ($keyfile === '') {
    fwrite(STDERR, "Missing keyfile\n");
    exit(1);
}

$server = new Quic\ServerConnection('127.0.0.1', $port, [
    'certfile' => $certfile,
    'keyfile' => $keyfile,
    'response' => null,
]);

$socket = $server->getPollStream();
stream_set_blocking($socket, false);

fwrite(STDERR, "listening on 127.0.0.1:" . $server->getLocalAddress()['port'] . PHP_EOL);

$fiber = new Fiber(static function () use ($server, $socket, $response): string {
    $peer = null;
    $accepted = null;
    $responded = false;
    $requestBody = '';

    while (true) {
        $server->flush();

        if (!($peer instanceof Quic\ServerPeer)) {
            $peer = $server->popAcceptedPeer();
            if ($peer instanceof Quic\ServerPeer) {
                $peerAddress = $peer->getPeerAddress();
                fwrite(STDERR, "accepted peer " . $peerAddress['address'] . ':' . $peerAddress['port'] . PHP_EOL);
            }
        }

        if ($accepted === null && $peer instanceof Quic\ServerPeer) {
            $accepted = $peer->popAcceptedStream();
        }

        if ($accepted instanceof Quic\Stream) {
            $chunk = $accepted->read();
            if ($chunk !== '') {
                $requestBody .= $chunk;
            }

            if (!$responded && $accepted->isFinished() && $accepted->isWritable()) {
                $accepted->write($response, true);
                $server->flush();
                $responded = true;
            }

            if ($responded && $accepted->isFinished() && $requestBody !== '') {
                if ($peer instanceof Quic\ServerPeer) {
                    $peer->close();
                    $server->flush();
                }

                return $requestBody;
            }
        }

        $event = quic_fiber_await_poll($socket, $peer?->getTimeout() ?? $server->getTimeout() ?? 50);

        if (($event['timed_out'] ?? false) === true) {
            $server->handleExpiry();
            continue;
        }

        $server->handleReadable();
    }
});

try {
    $requestBody = quic_run_poll_fiber($fiber);
    if ($requestBody !== '') {
        fwrite(STDOUT, $requestBody);
    }
} finally {
    fclose($socket);
    $server->close();
}
