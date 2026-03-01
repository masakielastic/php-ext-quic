--TEST--
Quic\ClientConnection rejects invalid constructor options and premature operations
--SKIPIF--
<?php
if (!extension_loaded('quic')) {
    echo 'skip extension not loaded';
}
?>
--FILE--
<?php
$cases = [
    static function (): void {
        new Quic\ClientConnection('127.0.0.1', 0);
    },
    static function (): void {
        new Quic\ClientConnection('127.0.0.1', 4433, [
            'verify_peer' => 1,
        ]);
    },
    static function (): void {
        new Quic\ClientConnection('127.0.0.1', 4433, [
            'cafile' => false,
        ]);
    },
];

foreach ($cases as $case) {
    try {
        $case();
        echo "no-error\n";
    } catch (Throwable $e) {
        echo get_class($e), PHP_EOL;
        echo $e->getMessage(), PHP_EOL;
    }
}

$client = new Quic\ClientConnection('127.0.0.1', 4433, [
    'verify_peer' => false,
]);

try {
    $client->handleReadable();
} catch (Throwable $e) {
    echo get_class($e), PHP_EOL;
    echo $e->getMessage(), PHP_EOL;
}

try {
    $client->openBidirectionalStream();
} catch (Throwable $e) {
    echo get_class($e), PHP_EOL;
    echo $e->getMessage(), PHP_EOL;
}
?>
--EXPECTF--
ValueError
Quic\ClientConnection::__construct(): Argument #2 ($port) must be between 1 and 65535
TypeError
Option "verify_peer" must be of type bool
TypeError
Option "cafile" must be of type ?string
Quic\Exception
Handshake has not been started
Quic\Exception
Handshake has not been started
