<?php
// JSON API: POST an exception.txt (multipart field "file", or the raw text as the request body)
// and get the translation back. Nothing is stored.
//
//   curl -s -F file=@exception.txt https://<host>/api.php
//   curl -s --data-binary @exception.txt https://<host>/api.php

require_once __DIR__ . '/lib/config.php';
require_once __DIR__ . '/lib/translator.php';

header('Content-Type: application/json');
$config = stellar_config();

function fail($code, $msg)
{
	http_response_code($code);
	echo json_encode(array('error' => $msg));
	exit();
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
	fail(405, 'POST an exception.txt');
}
if (isset($_FILES['file']) && $_FILES['file']['error'] === UPLOAD_ERR_OK) {
	if ($_FILES['file']['size'] > $config['max_upload_bytes']) {
		fail(413, 'file too large');
	}
	$text = file_get_contents($_FILES['file']['tmp_name']);
} else {
	$text = file_get_contents('php://input', false, null, 0, $config['max_upload_bytes'] + 1);
	if (strlen($text) > $config['max_upload_bytes']) {
		fail(413, 'file too large');
	}
}
if ($text === false || trim($text) === '') {
	fail(400, 'empty request');
}
try {
	$sd = new SymbolData($config['data_dir']);
} catch (Exception $e) {
	fail(503, 'symbol data not available');
}
$result = translate_report(parse_exception_text($text), $sd, $config);
if ($result['error'] !== null) {
	http_response_code(422);
}
echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
