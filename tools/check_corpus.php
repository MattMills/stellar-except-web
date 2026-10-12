<?php
// Translate every *.txt under a directory and print how many game frames get names, per version.
// Prints only counts (no file names or contents), so it can be run over private uploads.
//
//   php tools/check_corpus.php <exceptions dir> [data dir]

require_once __DIR__ . '/../lib/config.php';
require_once __DIR__ . '/../lib/translator.php';

if (PHP_SAPI !== 'cli') {
	http_response_code(404);
	exit();
}
if ($argc < 2) {
	fwrite(STDERR, "usage: php tools/check_corpus.php <exceptions dir> [data dir]\n");
	exit(1);
}
$config = stellar_config();
$sd = new SymbolData($argc > 2 ? $argv[2] : $config['data_dir']);
$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($argv[1], FilesystemIterator::SKIP_DOTS));
$stats = array();
$t0 = microtime(true);
$n = 0;
foreach ($it as $file) {
	if (substr($file->getFilename(), -4) !== '.txt') {
		continue;
	}
	$r = translate_report(parse_exception_text(file_get_contents($file->getPathname())), $sd, $config);
	$v = $r['version'] === null ? '?' : $r['version'];
	if (!isset($stats[$v])) {
		$stats[$v] = array('files' => 0, 'unsupported' => 0, 'game' => 0, 'named' => 0, 'unnamed' => 0, 'no_address' => 0, 'other' => 0, 'functions' => array(), 'platform' => array());
	}
	$s = &$stats[$v];
	$s['files']++;
	$n++;
	if ($r['error'] !== null) {
		$s['unsupported']++;
		continue;
	}
	$p = $r['build']['platform'];
	$s['platform'][$p] = isset($s['platform'][$p]) ? $s['platform'][$p] + 1 : 1;
	foreach ($r['frames'] as $f) {
		if (empty($f['game'])) {
			continue;
		}
		$s['game']++;
		if ($f['status'] === 'named' || $f['status'] === 'unnamed') {
			$s[$f['status']]++;
			$s['functions'][$r['build']['id'] . $f['function']] = $f['status'] === 'named';
		} elseif ($f['status'] === 'no_address') {
			$s['no_address']++;
		} else {
			$s['other']++;
		}
	}
	unset($s);
}
uksort($stats, 'version_compare');
printf("%-9s %6s %6s %7s %7s %7s %8s %6s %10s %10s  %s\n", 'version', 'files', 'unsup', 'frames', 'named', 'unnamed', 'no_addr', 'other', 'functions', 'named_fn', 'platforms');
$tot = array_fill_keys(array('files', 'unsupported', 'game', 'named', 'unnamed', 'no_address', 'other', 'fn', 'fn_named'), 0);
foreach ($stats as $v => $s) {
	$fn = count($s['functions']);
	$fnn = count(array_filter($s['functions']));
	$pl = array();
	foreach ($s['platform'] as $k => $c) {
		$pl[] = "$k:$c";
	}
	printf("%-9s %6d %6d %7d %7d %7d %8d %6d %10d %10d  %s\n", $v, $s['files'], $s['unsupported'], $s['game'], $s['named'], $s['unnamed'], $s['no_address'], $s['other'], $fn, $fnn, implode(' ', $pl));
	foreach (array('files', 'unsupported', 'named', 'unnamed', 'no_address', 'other') as $k) {
		$tot[$k] += $s[$k];
	}
	$tot['game'] += $s['game'];
	$tot['fn'] += $fn;
	$tot['fn_named'] += $fnn;
}
printf("%-9s %6d %6d %7d %7d %7d %8d %6d %10d %10d\n", 'total', $tot['files'], $tot['unsupported'], $tot['game'], $tot['named'], $tot['unnamed'], $tot['no_address'], $tot['other'], $tot['fn'], $tot['fn_named']);
printf("%d files in %.1fs\n", $n, microtime(true) - $t0);
