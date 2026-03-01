--TEST--
Quic client and server getStream compatibility aliases are deprecated
--SKIPIF--
<?php
if (!extension_loaded('quic')) {
    echo 'skip extension not loaded';
}
?>
--FILE--
<?php
$messages = [];
set_error_handler(static function (int $severity, string $message) use (&$messages): bool {
    if ($severity === E_DEPRECATED) {
        $messages[] = $message;
        return true;
    }

    return false;
});

$client = new Quic\ClientConnection('127.0.0.1', 4433, [
    'verify_peer' => false,
]);
$clientStream = $client->getStream();

$server = new Quic\ServerConnection('127.0.0.1', 0);
$serverStream = $server->getStream();

var_dump(is_resource($clientStream));
var_dump(is_resource($serverStream));
var_dump(count($messages));
var_dump(str_contains($messages[0] ?? '', 'Quic\\ClientConnection::getStream'));
var_dump(str_contains($messages[1] ?? '', 'Quic\\ServerConnection::getStream'));

fclose($clientStream);
fclose($serverStream);
$client->close();
$server->close();
restore_error_handler();
?>
--EXPECT--
bool(true)
bool(true)
int(2)
bool(true)
bool(true)
