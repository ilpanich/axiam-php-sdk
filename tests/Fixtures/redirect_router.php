<?php

// Test fixture router for `php -S`: logs every request path to the file named by AXIAM_TEST_LOG,
// answers the discovery and JWKS paths with a 302 to /redirect-target.
declare(strict_types=1);

$path = parse_url((string) $_SERVER['REQUEST_URI'], PHP_URL_PATH);
file_put_contents((string) getenv('AXIAM_TEST_LOG'), $path . "\n", FILE_APPEND);
if ($path === '/.well-known/openid-configuration' || $path === '/oauth2/jwks') {
    header('Location: /redirect-target', true, 302);
    exit;
}
http_response_code(200);
echo '{"keys":[]}';
