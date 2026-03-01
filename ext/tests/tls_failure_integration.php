<?php

declare(strict_types=1);

function pumpFailureOnce(
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
        try {
            $server->handleExpiry();
        } catch (Quic\ProtocolException $e) {
            if (
                !str_contains($e->getMessage(), 'ERR_CLOSING') &&
                !str_contains($e->getMessage(), 'ERR_DRAINING') &&
                !str_contains($e->getMessage(), 'ERR_DROP_CONN')
            ) {
                throw $e;
            }
        }
        $client->handleExpiry();
        return;
    }

    foreach ($read as $resource) {
        if ($resource === $serverStream) {
            try {
                $server->handleReadable();
            } catch (Quic\ProtocolException $e) {
                if (
                    !str_contains($e->getMessage(), 'ERR_CLOSING') &&
                    !str_contains($e->getMessage(), 'ERR_DRAINING') &&
                    !str_contains($e->getMessage(), 'ERR_DROP_CONN')
                ) {
                    throw $e;
                }
            }
        } elseif ($resource === $clientStream) {
            $client->handleReadable();
        }
    }
}

function captureServerNameFailure(string $cert, string $key): Throwable
{
    $server = new Quic\ServerConnection('127.0.0.1', 0, [
        'certfile' => $cert,
        'keyfile' => $key,
        'response' => null,
    ]);
    $serverStream = $server->getPollStream();
    stream_set_blocking($serverStream, false);

    $client = new Quic\ClientConnection('127.0.0.1', $server->getLocalAddress()['port'], [
        'verify_peer' => true,
        'cafile' => $cert,
        'server_name' => 'example.invalid',
    ]);
    $clientStream = $client->getPollStream();
    stream_set_blocking($clientStream, false);
    $client->startHandshake();

    try {
        $deadline = microtime(true) + 5.0;

        while (microtime(true) < $deadline) {
            try {
                pumpFailureOnce($server, $serverStream, $client, $clientStream);
            } catch (Throwable $e) {
                return $e;
            }
        }
    } finally {
        fclose($clientStream);
        $client->close();
        fclose($serverStream);
        $server->close();
    }

    throw new RuntimeException('server-name verification failure did not trigger');
}

function captureMissingServerFileFailure(): Throwable
{
    $server = new Quic\ServerConnection('127.0.0.1', 0, [
        'certfile' => '/tmp/quic-missing-server.crt',
        'keyfile' => '/tmp/quic-missing-server.key',
        'response' => null,
    ]);
    $serverStream = $server->getPollStream();
    stream_set_blocking($serverStream, false);

    $client = new Quic\ClientConnection('127.0.0.1', $server->getLocalAddress()['port'], [
        'verify_peer' => false,
    ]);
    $clientStream = $client->getPollStream();
    stream_set_blocking($clientStream, false);
    $client->startHandshake();

    try {
        $deadline = microtime(true) + 5.0;

        while (microtime(true) < $deadline) {
            try {
                pumpFailureOnce($server, $serverStream, $client, $clientStream);
            } catch (Throwable $e) {
                return $e;
            }
        }
    } finally {
        fclose($clientStream);
        $client->close();
        fclose($serverStream);
        $server->close();
    }

    throw new RuntimeException('server cert/key failure did not trigger');
}

$missingCafileFailure = null;

try {
    $client = new Quic\ClientConnection('127.0.0.1', 4433, [
        'verify_peer' => true,
        'cafile' => '/tmp/quic-missing-ca.pem',
    ]);
    $client->startHandshake();
} catch (Throwable $e) {
    $missingCafileFailure = $e;
} finally {
    if (isset($client)) {
        $client->close();
    }
}

$serverNameFailure = captureServerNameFailure(
    '/tmp/nghttp3-localhost.crt',
    '/tmp/nghttp3-localhost.key',
);

$missingServerFileFailure = captureMissingServerFileFailure();

var_dump($missingCafileFailure instanceof Quic\TlsException);
var_dump(str_contains($missingCafileFailure?->getMessage() ?? '', 'gnutls_certificate_set_x509_trust_file('));
var_dump($serverNameFailure instanceof Quic\ProtocolException);
var_dump(($serverNameFailure->getMessage() ?? '') === 'ERR_CRYPTO');
var_dump($missingServerFileFailure instanceof Quic\TlsException);
var_dump(str_contains($missingServerFileFailure->getMessage(), 'gnutls_certificate_set_x509_key_file() failed'));
