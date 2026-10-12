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
//
// Frame lines seen in the wild:
//   "  1    stellaris.exe            PHYSFS_swapSLE64 (+ 9322603)"        3.x: module, export + offset
//   "  1                             PHYSFS_writeUBE64 (+ 4790264)"       4.x: the module column is empty
//   "  5                             (function-name not available) (+ 0)" no address at all
//   " 18   some.dll     `anonymous namespace'::worker (database_workers.cpp: 68)"  symbol with source line

// Module column: a file name with an executable-module extension.
const MODULE_RE = '/^(\S+\.(?:exe|dll|sys|drv|ocx|cpl))\s+(.*)$/i';

function parse_frame_line($line)
{
	if (!preg_match('/^\s*(\d+)\s+(.*?)\s*$/', $line, $m)) {
		return null;
	}
	$frame = array('frame' => (int)$m[1], 'module' => '', 'symbol' => '', 'sign' => '+', 'offset' => null, 'location' => null);
	$rest = $m[2];
	if (preg_match('/^(.*?)\s*\(\s*([+-])\s*(\d+)\s*\)$/', $rest, $t)) {
		// "<symbol> (+ <offset>)"
		$head = $t[1];
		$frame['sign'] = $t[2];
		$frame['offset'] = (int)$t[3];
	} elseif (preg_match('/^(.*?)\s*\(([^()]*:\s*\d+)\)$/', $rest, $t)) {
		// "<symbol> (<file>: <line>)" for modules with debug information
		$head = $t[1];
		$frame['location'] = trim($t[2]);
	} else {
		return null;
	}
	if (preg_match(MODULE_RE, $head, $t)) {
		$frame['module'] = $t[1];
		$head = $t[2];
	}
	$frame['symbol'] = trim($head);
	if ($frame['symbol'] === '') {
		return null;
	}
	return $frame;
}

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
		if ($exception === '' && preg_match('/^\s*(Unhandled exception|An exception)/i', $line)) {
			$exception = trim($line);
			continue;
		}
		$f = parse_frame_line($line);
		if ($f !== null) {
			$frames[] = $f;
		}
	}
	// macOS crash reports list frames as "N  module  0x<address> symbol + offset"
	$macos = count($frames) == 0 && preg_match('/^\s*\d+\s+\S+\s+0x[0-9a-fA-F]{8,}\s+\S/m', $text);
	return array('attr' => $attr, 'exception' => $exception, 'frames' => $frames, 'macos' => (bool)$macos);
}

// Collapse frames that repeat many times (deep recursion) into one row with a loop count.
function dedupe_frames($frames, $threshold)
{
	$key = function ($f) {
		return $f['module'] . '|' . $f['symbol'] . '|' . $f['sign'] . $f['offset'] . '|' . $f['location'];
	};
	$count = array();
	foreach ($frames as $f) {
		$k = $key($f);
		$count[$k] = isset($count[$k]) ? $count[$k] + 1 : 1;
	}
	$seen = array();
	$out = array();
	foreach ($frames as $f) {
		$k = $key($f);
		$f['loop_count'] = $count[$k];
		// "(function-name not available) (+ 0)" lines repeat without being a loop
		if ($count[$k] >= $threshold && $f['offset'] !== 0) {
			if (isset($seen[$k])) {
				continue;
			}
			$seen[$k] = true;
		}
		$out[] = $f;
	}
	return $out;
}
