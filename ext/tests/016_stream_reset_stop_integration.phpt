--TEST--
Quic\Stream reset and stop keep the connection usable
--SKIPIF--
<?php
require __DIR__ . '/integration_skipif.inc';
quic_integration_skipif([
    'require_env' => true,
    'require_certs' => true,
    'probe_bind' => true,
]);
?>
--FILE--
<?php
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
stream_set_blocking($serverStream, false);
stream_set_blocking($clientStream, false);

$peer = null;
$resetStream = null;
$stopStream = null;
$serverResetStream = null;
$serverStopStream = null;
$stopRequest = '';
$deadline = microtime(true) + 5.0;

$client->startHandshake();

while (microtime(true) < $deadline) {
    $client->flush();
    $server->flush();

    if (!$peer instanceof Quic\ServerPeer) {
        $peer = $server->popAcceptedPeer();
    }

    if ($peer instanceof Quic\ServerPeer) {
        while (($candidate = $peer->popAcceptedStream()) instanceof Quic\Stream) {
            if (!$serverResetStream instanceof Quic\Stream) {
                $serverResetStream = $candidate;
                continue;
            }

            if (!$serverStopStream instanceof Quic\Stream) {
                $serverStopStream = $candidate;
                break;
            }
        }
    }

    if ($client->isHandshakeComplete() && !$resetStream instanceof Quic\Stream) {
        $resetStream = $client->openBidirectionalStream();
        $resetStream->write("reset-me\n");
        $resetStream->reset(42);
    }

    if (
        $client->isHandshakeComplete() &&
        $resetStream instanceof Quic\Stream &&
        $serverResetStream instanceof Quic\Stream &&
        !$stopStream instanceof Quic\Stream
    ) {
        $stopStream = $client->openBidirectionalStream();
        $stopStream->write("stop-me\n");
        $stopStream->stop(7);
    }

    if ($serverStopStream instanceof Quic\Stream) {
        $chunk = $serverStopStream->read();
        if ($chunk !== '') {
            $stopRequest .= $chunk;
        }
    }

    if (
        $resetStream instanceof Quic\Stream &&
        $stopStream instanceof Quic\Stream &&
        $stopRequest === "stop-me\n"
    ) {
        break;
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

var_dump($resetStream instanceof Quic\Stream);
var_dump($resetStream?->isFinished());
var_dump($resetStream?->isWritable());
var_dump($stopStream instanceof Quic\Stream);
var_dump($stopStream?->isWritable());
var_dump($stopStream?->read());
var_dump($stopRequest);

fclose($serverStream);
fclose($clientStream);
$server->close();
$client->close();
?>
--EXPECT--
bool(true)
bool(true)
bool(false)
bool(true)
bool(true)
string(0) ""
string(8) "stop-me
"
