--TEST--
Quic\ServerConnection rejects invalid constructor options
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
        new Quic\ServerConnection('', 0);
    },
    static function (): void {
        new Quic\ServerConnection('127.0.0.1', -1);
    },
    static function (): void {
        new Quic\ServerConnection('127.0.0.1', 0, [
            'certfile' => false,
        ]);
    },
    static function (): void {
        new Quic\ServerConnection('127.0.0.1', 0, [
            'response' => false,
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
?>
--EXPECTF--
ValueError
Quic\ServerConnection::__construct(): Argument #1 ($host) must not be empty
ValueError
Quic\ServerConnection::__construct(): Argument #2 ($port) must be between 0 and 65535
TypeError
Option "certfile" must be of type ?string
TypeError
Option "response" must be of type ?string
