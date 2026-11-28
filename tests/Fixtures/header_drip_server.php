<?php

// Test fixture: a raw-socket HTTP server that accepts connections and drips response HEADER bytes
// one at a time, never finishing. Usage: php header_drip_server.php <port> <counter-file>
declare(strict_types=1);

$server = stream_socket_server('tcp://127.0.0.1:' . $argv[1], $errno, $errstr);
if ($server === false) {
    exit(1);
}
$conns = [];
$end = time() + 40;
while (time() < $end) {
    $r = [$server];
    $w = $e = null;
    if (stream_select($r, $w, $e, 0, 200000) > 0) {
        $c = stream_socket_accept($server, 0);
        if ($c !== false) {
            $conns[] = $c;
            file_put_contents($argv[2], (string) count($conns));
            fwrite($c, "HTTP/1.1 200 OK\r\n");
        }
    }
    foreach ($conns as $c) {
        @fwrite($c, "X-Drip: a\r\n");
    }
    usleep(200000);
}
