<?php

declare(strict_types=1);

if ($argc < 3) {
    fwrite(STDERR, "Usage: php client_ping.php <host> <port> [message]\n");
    exit(1);
}

$host = $argv[1];
$port = (int) $argv[2];
$message = $argv[3] ?? "ping\n";

$client = new Quic\ClientConnection($host, $port, [
    'verify_peer' => false,
]);

$socket = $client->getStream();
$client->startHandshake();

$stream = null;
$response = '';
$deadline = microtime(true) + 5.0;

$isExpectedClose = static function (Throwable $e, bool $streamOpened): bool {
    if (!($e instanceof Quic\ProtocolException)) {
        return false;
    }

    return $streamOpened && (
        str_contains($e->getMessage(), 'ERR_CLOSING') ||
        str_contains($e->getMessage(), 'ERR_DRAINING')
    );
};

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
                break;
            }
        }
    }

    $read = [$socket];
    $write = null;
    $except = null;
    $timeout = $client->getTimeout() ?? 50;
    $ready = stream_select($read, $write, $except, intdiv($timeout, 1000), ($timeout % 1000) * 1000);

    if ($ready === false) {
        throw new RuntimeException('stream_select failed');
    }

    if ($ready === 0) {
        try {
            $client->handleExpiry();
        } catch (Throwable $e) {
            if ($isExpectedClose($e, $stream instanceof Quic\Stream)) {
                if ($stream instanceof Quic\Stream) {
                    $response .= $stream->read();
                }
                break;
            }

            throw $e;
        }
        continue;
    }

    try {
        $client->handleReadable();
    } catch (Throwable $e) {
        if ($isExpectedClose($e, $stream instanceof Quic\Stream)) {
            if ($stream instanceof Quic\Stream) {
                $response .= $stream->read();
            }
            break;
        }

        throw $e;
    }
}

if ($response !== '') {
    fwrite(STDOUT, $response);
}

fclose($socket);
$client->close();
