--TEST--
Quic poll streams reject direct I/O but remain usable with stream_select
--SKIPIF--
<?php
if (!extension_loaded('quic')) {
    echo 'skip extension not loaded';
}
?>
--FILE--
<?php
$client = new Quic\ClientConnection('127.0.0.1', 4433, [
    'verify_peer' => false,
]);
$server = new Quic\ServerConnection('127.0.0.1', 0);

$clientStream = $client->getPollStream();
$serverStream = $server->getPollStream();

$errors = [];
set_error_handler(static function (int $errno, string $message) use (&$errors): bool {
    $errors[] = $message;
    return true;
});

$read = [$clientStream];
$write = null;
$except = null;
$ready = stream_select($read, $write, $except, 0, 0);

$clientRead = @fread($clientStream, 1);
$clientWrite = @fwrite($clientStream, "x");
$serverWrite = @fwrite($serverStream, "x");

@fclose($clientStream);
@fclose($serverStream);

restore_error_handler();

$client->close();
$server->close();

var_dump($clientRead);
var_dump($clientWrite);
var_dump($serverWrite);
var_dump($ready);
var_dump(count($errors));
foreach ($errors as $message) {
    echo $message, PHP_EOL;
}
?>
--EXPECTF--
bool(false)
bool(false)
bool(false)
int(0)
int(3)
fread(): Quic\ClientConnection::getPollStream() is a readiness-only QUIC poll stream; use handleReadable() on the connection instead
fwrite(): Quic\ClientConnection::getPollStream() is a readiness-only QUIC poll stream; use flush() on the connection instead
fwrite(): Quic\ServerConnection::getPollStream() is a readiness-only QUIC poll stream; use flush() on the connection instead
