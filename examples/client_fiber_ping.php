<?php

declare(strict_types=1);

require __DIR__ . '/fiber_scheduler.php';

if ($argc < 3) {
    fwrite(STDERR, "Usage: php client_fiber_ping.php <host> <port> [message]\n");
    exit(1);
}

quic_require_fiber_support();

$host = $argv[1];
$port = (int) $argv[2];
$message = $argv[3] ?? "ping\n";

$client = new Quic\ClientConnection($host, $port, [
    'verify_peer' => false,
]);

$socket = $client->getPollStream();
stream_set_blocking($socket, false);

$isExpectedClose = static function (Throwable $e, bool $streamOpened): bool {
    if (!($e instanceof Quic\ProtocolException)) {
        return false;
    }

    return $streamOpened && (
        str_contains($e->getMessage(), 'ERR_CLOSING') ||
        str_contains($e->getMessage(), 'ERR_DRAINING')
    );
};

$fiber = new Fiber(static function () use ($client, $socket, $message, $isExpectedClose): string {
    $client->startHandshake();

    $stream = null;
    $response = '';
    $deadline = microtime(true) + 5.0;

    while (microtime(true) < $deadline) {
        $client->flush();

        if ($client->isHandshakeComplete() && !($stream instanceof Quic\Stream)) {
            $stream = $client->openBidirectionalStream();
            $stream->write($message, true);
        }

        if ($stream instanceof Quic\Stream) {
            $chunk = $stream->read();
            if ($chunk !== '') {
                $response .= $chunk;
                if ($stream->isFinished()) {
                    return $response;
                }
            }
        }

        $event = quic_fiber_await_poll($socket, $client->getTimeout() ?? 50);

        try {
            if (($event['timed_out'] ?? false) === true) {
                $client->handleExpiry();
                continue;
            }

            $client->handleReadable();
        } catch (Throwable $e) {
            if ($isExpectedClose($e, $stream instanceof Quic\Stream)) {
                if ($stream instanceof Quic\Stream) {
                    $response .= $stream->read();
                }

                return $response;
            }

            throw $e;
        }
    }

    return $response;
});

try {
    $response = quic_run_poll_fiber($fiber);
    if ($response !== '') {
        fwrite(STDOUT, $response);
    }
} finally {
    fclose($socket);
    $client->close();
}
