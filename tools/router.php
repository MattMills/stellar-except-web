<?php
// Router for PHP's built-in web server (development only):
//   php -S 127.0.0.1:8099 -t . tools/router.php
// Serves existing files (api.php, ...) and sends everything else (/, /cached/<token>) to index.php.

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$file = realpath(__DIR__ . '/..' . $path);
if ($path !== '/' && $file !== false && is_file($file) && strpos($file, realpath(__DIR__ . '/..')) === 0) {
	return false;
}
$_SERVER['SCRIPT_NAME'] = '/index.php';
require __DIR__ . '/../index.php';
