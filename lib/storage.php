<?php
// Stored uploads and permalinks, compatible with v1: uploads are kept as
// <uploads_dir>/YYYY/MM/DD/<unix time>_<ip>.txt and the permalink is /cached/<base64(time)>, so old
// links keep working and are now translated by v2. Translations are cached next to the upload
// as <file>.v2.json.

function store_upload($tmp_path, $config)
{
	$t = time();
	$dir = rtrim($config['uploads_dir'], '/') . '/' . date('Y/m/d/', $t);
	@mkdir($dir, 0777, true);
	// one upload per second keeps the v1 permalink scheme unambiguous
	while (count(glob($dir . $t . '_*.txt')) > 0) {
		$t++;
	}
	$name = $t . ($config['ip_in_filename'] ? '_' . preg_replace('/[^0-9a-fA-F:.]/', '', $_SERVER['REMOTE_ADDR']) : '_') . '.txt';
	if (!@move_uploaded_file($tmp_path, $dir . $name)) {
		return null;
	}
	return array('time' => $t, 'path' => $dir . $name);
}

function permalink_token($time)
{
	return rtrim(base64_encode((string)$time), '=');
}

// The stored upload for a permalink token, or null.
function find_upload($token, $config)
{
	$t = base64_decode($token . str_repeat('=', (4 - strlen($token) % 4) % 4), true);
	if ($t === false || !ctype_digit($t)) {
		return null;
	}
	$files = glob(rtrim($config['uploads_dir'], '/') . '/' . date('Y/m/d/', (int)$t) . $t . '_*.txt');
	if (!$files) {
		return null;
	}
	return array('time' => (int)$t, 'path' => $files[0]);
}

function cached_translation($upload_path, $data_stamp)
{
	$c = @file_get_contents($upload_path . '.v2.json');
	if ($c === false) {
		return null;
	}
	$j = json_decode($c, true);
	// a new data set invalidates old translations
	if (!is_array($j) || !isset($j['data_stamp']) || $j['data_stamp'] !== $data_stamp) {
		return null;
	}
	return $j;
}

function cache_translation($upload_path, $result, $data_stamp)
{
	$result['data_stamp'] = $data_stamp;
	@file_put_contents($upload_path . '.v2.json', json_encode($result));
}
