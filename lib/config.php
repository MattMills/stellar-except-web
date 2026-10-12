<?php
// Configuration. Override any key in config.local.php (not in git), which must return an array:
//   <?php return array('data_dir' => '/srv/stellar-except/webdata');

function stellar_config()
{
	static $config = null;
	if ($config !== null) {
		return $config;
	}
	$config = array(
		// static data written by `stellar-fnmatch webdata` (builds.json, names.*, builds/)
		'data_dir' => __DIR__ . '/../webdata',
		// keep uploaded exception.txt files (and their translation) so results get a permalink
		'store_uploads' => true,
		'uploads_dir' => __DIR__ . '/../exceptions',
		// v1 named stored files <unix time>_<client ip>.txt; set false to leave the ip out
		'ip_in_filename' => true,
		'max_upload_bytes' => 10000000,
		// optional site chrome; when unset or missing the page uses a minimal built-in layout
		'header' => '/var/www/html/stellar-web/header.php',
		'footer' => '/var/www/html/stellar-web/footer.php',
		// frames repeated at least this often are collapsed into one row (recursion loops)
		'loop_threshold' => 5,
	);
	$local = __DIR__ . '/../config.local.php';
	if (is_file($local)) {
		$over = include $local;
		if (is_array($over)) {
			$config = array_merge($config, $over);
		}
	}
	return $config;
}
