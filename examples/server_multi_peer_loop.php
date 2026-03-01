<?php

declare(strict_types=1);

if ($argc < 5) {
    fwrite(
        STDERR,
        "Usage: php server_multi_peer_loop.php <port> <certfile> <keyfile> <max-peers> [response]\n"
    );
    exit(1);
}

$port = (int) $argv[1];
$certfile = $argv[2];
$keyfile = $argv[3];
$maxPeers = (int) $argv[4];
$response = $argv[5] ?? "server response\n";

if ($keyfile === '') {
    fwrite(STDERR, "Missing keyfile\n");
    exit(1);
}

if ($maxPeers <= 0) {
    fwrite(STDERR, "max-peers must be greater than 0\n");
    exit(1);
}

$server = new Quic\ServerConnection('127.0.0.1', $port, [
    'certfile' => $certfile,
    'keyfile' => $keyfile,
    'response' => null,
]);

$socket = $server->getPollStream();
$peerStates = [];
$completedPeers = 0;

fwrite(STDERR, "listening on 127.0.0.1:" . $server->getLocalAddress()['port'] . PHP_EOL);

while ($completedPeers < $maxPeers) {
    $server->flush();

    while (($peer = $server->popAcceptedPeer()) instanceof Quic\ServerPeer) {
        $peerId = spl_object_id($peer);
        $peerAddress = $peer->getPeerAddress();

        $peerStates[$peerId] = [
            'peer' => $peer,
            'stream' => null,
            'body' => '',
            'responded' => false,
        ];

        fwrite(STDERR, "accepted peer " . $peerAddress['address'] . ':' . $peerAddress['port'] . PHP_EOL);
    }

    foreach ($peerStates as $peerId => &$state) {
        if (!($state['stream'] instanceof Quic\Stream)) {
            $state['stream'] = $state['peer']->popAcceptedStream();
        }

        if (!($state['stream'] instanceof Quic\Stream)) {
            continue;
        }

        $chunk = $state['stream']->read();
        if ($chunk !== '') {
            $state['body'] .= $chunk;
        }

        if (
            !$state['responded'] &&
            $state['stream']->isFinished() &&
            $state['stream']->isWritable()
        ) {
            $state['stream']->write($response, true);
            $server->flush();
            $state['responded'] = true;
        }

        if ($state['responded'] && $state['stream']->isFinished() && $state['body'] !== '') {
            fwrite(STDOUT, $state['body']);
            $state['peer']->close();
            $server->flush();
            unset($peerStates[$peerId]);
            $completedPeers++;
        }
    }
    unset($state);

    $read = [$socket];
    $write = null;
    $except = null;

    $timeouts = [$server->getTimeout()];
    foreach ($peerStates as $state) {
        $timeouts[] = $state['peer']->getTimeout();
    }
    $timeouts = array_values(array_filter($timeouts, static fn($value) => $value !== null));

    $timeout = $timeouts ? max(0, min($timeouts)) : 50;
    $ready = stream_select($read, $write, $except, intdiv($timeout, 1000), ($timeout % 1000) * 1000);

    if ($ready === false) {
        throw new RuntimeException('stream_select failed');
    }

    if ($ready === 0) {
        $server->handleExpiry();
        continue;
    }

    $server->handleReadable();
}

fclose($socket);
$server->close();
