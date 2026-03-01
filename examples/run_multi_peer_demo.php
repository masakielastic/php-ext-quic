<?php

declare(strict_types=1);

if ($argc < 3) {
    fwrite(
        STDERR,
        "Usage: php run_multi_peer_demo.php <certfile> <keyfile> [message1] [message2]\n"
    );
    exit(1);
}

if (!extension_loaded('quic')) {
    fwrite(STDERR, "The quic extension must be loaded before running this script.\n");
    exit(1);
}

$certfile = $argv[1];
$keyfile = $argv[2];
$message1 = $argv[3] ?? "ping-1\n";
$message2 = $argv[4] ?? "ping-2\n";

$extensionPath = dirname(__DIR__) . '/ext/modules/quic.so';
$serverScript = __DIR__ . '/server_multi_peer_loop.php';
$clientScript = __DIR__ . '/client_ping.php';

$serverCommand = [
    PHP_BINARY,
    '-d',
    'extension=' . $extensionPath,
    $serverScript,
    '0',
    $certfile,
    $keyfile,
    '2',
    "server response\n",
];

$descriptors = [
    0 => ['pipe', 'r'],
    1 => ['pipe', 'w'],
    2 => ['pipe', 'w'],
];

$server = proc_open($serverCommand, $descriptors, $serverPipes, __DIR__);
if (!is_resource($server)) {
    throw new RuntimeException('Failed to start server_multi_peer_loop.php');
}

fclose($serverPipes[0]);
stream_set_blocking($serverPipes[2], false);

$port = null;
$serverLog = '';
$deadline = microtime(true) + 5.0;

while (microtime(true) < $deadline) {
    $chunk = stream_get_contents($serverPipes[2]);
    if ($chunk !== false && $chunk !== '') {
        $serverLog .= $chunk;

        if (preg_match('/listening on 127\\.0\\.0\\.1:(\\d+)/', $serverLog, $matches)) {
            $port = (int) $matches[1];
            break;
        }
    }

    usleep(10_000);
}

if (!is_int($port)) {
    proc_terminate($server);
    throw new RuntimeException("Did not receive server port.\n" . $serverLog);
}

$runClient = static function (int $port, string $message) use ($extensionPath, $clientScript): string {
    $command = [
        PHP_BINARY,
        '-d',
        'extension=' . $extensionPath,
        $clientScript,
        '127.0.0.1',
        (string) $port,
        $message,
    ];
    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];

    $process = proc_open($command, $descriptors, $pipes, __DIR__);
    if (!is_resource($process)) {
        throw new RuntimeException('Failed to start client_ping.php');
    }

    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[2]);

    $status = proc_close($process);
    if ($status !== 0) {
        throw new RuntimeException("client_ping.php failed:\n" . $stderr);
    }

    return $stdout;
};

$client1 = $runClient($port, $message1);
$client2 = $runClient($port, $message2);

stream_set_blocking($serverPipes[1], true);
stream_set_blocking($serverPipes[2], true);

$serverStdout = stream_get_contents($serverPipes[1]);
fclose($serverPipes[1]);
$serverStderrRemainder = stream_get_contents($serverPipes[2]);
fclose($serverPipes[2]);

$serverStatus = proc_close($server);
if ($serverStatus !== 0) {
    throw new RuntimeException("server_multi_peer_loop.php failed:\n" . $serverLog . $serverStderrRemainder);
}

echo "client1=", trim($client1), PHP_EOL;
echo "client2=", trim($client2), PHP_EOL;
echo "server=", str_replace("\n", '|', trim($serverStdout)), PHP_EOL;
