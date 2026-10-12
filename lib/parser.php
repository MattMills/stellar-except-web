<?php
// exception.txt parsing.
//
//   Application: Stellaris
//   Version: 3.12.5
//   Date/Time: 2024-06-20 18:01:02
//
//   Unhandled exception C0000005 (EXCEPTION_ACCESS_VIOLATION) at address 0x00007FF6A1B2C3D4
//
//   Stack Trace:
//     1    stellaris.exe            PHYSFS_swapSLE64 (+ 9322603)

function parse_exception_text($text)
{
	$text = str_replace("\r", '', $text);
	$attr = array();
	$exception = '';
	$frames = array();
	foreach (explode("\n", $text) as $line) {
		if (preg_match('/^(Application|Version|Date\/Time):\s*(.*?)\s*$/', $line, $m) && !isset($attr[$m[1]])) {
			$attr[$m[1]] = $m[2];
			continue;
		}
		if ($exception === '' && preg_match('/^\s*(Unhandled exception|An exception)/', $line)) {
			$exception = trim($line);
			continue;
		}
		if (preg_match('/^\s*(\d+)\s+(\S+)\s+(.+?)\s*\(\s*([+-])\s*(\d+)\s*\)\s*$/', $line, $m)) {
			$frames[] = array(
				'frame' => (int)$m[1],
				'module' => $m[2],
				'symbol' => trim($m[3]),
				'sign' => $m[4],
				'offset' => (int)$m[5],
			);
		}
	}
	// macOS crash reports list frames as "N  module  0x<address> symbol + offset"
	$macos = count($frames) == 0 && preg_match('/^\s*\d+\s+\S+\s+0x[0-9a-fA-F]{8,}\s+\S/m', $text);
	return array('attr' => $attr, 'exception' => $exception, 'frames' => $frames, 'macos' => (bool)$macos);
}

// Collapse frames that repeat many times (deep recursion) into one row with a loop count.
function dedupe_frames($frames, $threshold)
{
	$count = array();
	foreach ($frames as $f) {
		$k = $f['module'] . '|' . $f['symbol'] . '|' . $f['sign'] . $f['offset'];
		$count[$k] = isset($count[$k]) ? $count[$k] + 1 : 1;
	}
	$seen = array();
	$out = array();
	foreach ($frames as $f) {
		$k = $f['module'] . '|' . $f['symbol'] . '|' . $f['sign'] . $f['offset'];
		$f['loop_count'] = $count[$k];
		if ($count[$k] >= $threshold) {
			if (isset($seen[$k])) {
				continue;
			}
			$seen[$k] = true;
		}
		$out[] = $f;
	}
	return $out;
}
