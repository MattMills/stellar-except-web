<?php
require_once __DIR__ . '/parser.php';
require_once __DIR__ . '/symbol_data.php';

// RVA of a stellaris.exe frame in a build, or null when its export is unknown.
function frame_rva($frame, $exports)
{
	if (!isset($exports[$frame['symbol']])) {
		return null;
	}
	$base = $exports[$frame['symbol']];
	return $frame['sign'] === '-' ? $base - $frame['offset'] : $base + $frame['offset'];
}

function is_game_frame($frame)
{
	return strcasecmp($frame['module'], 'stellaris.exe') === 0;
}

// Frame 1 is the faulting instruction; every other frame is a return address, which points just
// after a call, so its function is the one containing the byte before.
function lookup_rva($frame, $rva)
{
	return $frame['frame'] == 1 ? $rva : $rva - 1;
}

// How well a report fits a build: frames whose address falls inside a function and, for return
// addresses, right after a call instruction.
function build_fit($frames, $id, SymbolData $sd)
{
	$exports = $sd->exports($id);
	$checked = 0;
	$fit = 0;
	foreach ($frames as $f) {
		if (!is_game_frame($f) || $f['offset'] == 0) {
			continue;
		}
		$rva = frame_rva($f, $exports);
		if ($rva === null || $rva < 0) {
			continue;
		}
		$checked++;
		if ($sd->functionAt($id, lookup_rva($f, $rva)) === null) {
			continue;
		}
		if ($f['frame'] == 1 || $sd->isReturnAddress($id, $rva)) {
			$fit++;
		}
	}
	return array('checked' => $checked, 'fit' => $fit);
}

function translate_report($parsed, SymbolData $sd, $config)
{
	$attr = $parsed['attr'];
	$out = array(
		'attr' => $attr,
		'exception' => $parsed['exception'],
		'version' => null,
		'error' => null,
		'build' => null,
		'candidates' => array(),
		'frames' => array(),
		'frames_total' => count($parsed['frames']),
		'loops_removed' => 0,
	);
	if (!isset($attr['Application']) || stripos($attr['Application'], 'Stellaris') === false) {
		$out['error'] = 'This does not look like a Stellaris exception.txt (no "Application: Stellaris" line).';
		return $out;
	}
	if (!isset($attr['Version']) || !preg_match('/(\d+\.\d+(?:\.\d+)*)/', $attr['Version'], $m)) {
		$out['error'] = 'No game version found in the file.';
		return $out;
	}
	$out['version'] = $m[1];
	$frames = dedupe_frames($parsed['frames'], $config['loop_threshold']);
	$out['loops_removed'] = count($parsed['frames']) - count($frames);
	if (count($frames) == 0) {
		$out['error'] = !empty($parsed['macos'])
			? 'This is a macOS crash report; the translator handles the Windows builds only.'
			: 'No stack trace found in the file.';
		return $out;
	}
	$cands = $sd->candidates($out['version']);
	if (count($cands) == 0) {
		$out['error'] = 'Version ' . $out['version'] . ' is not supported (supported: 64-bit Windows builds from 2.3.0 on).';
		return $out;
	}
	// which build of this version the report came from (Steam, GOG, betas): first best fit wins,
	// candidates are ordered Steam first
	$best = null;
	foreach ($cands as $id) {
		$fit = build_fit($frames, $id, $sd);
		$b = $sd->build($id);
		$out['candidates'][] = array('id' => $id, 'platform' => $b['platform'], 'build_string' => $b['build_string'], 'checked' => $fit['checked'], 'fit' => $fit['fit']);
		if ($best === null || $fit['fit'] > $best['fit']) {
			$best = array('id' => $id, 'fit' => $fit['fit'], 'checked' => $fit['checked']);
		}
	}
	$id = $best['id'];
	$out['build'] = $sd->build($id);
	$out['build']['fit'] = $best['fit'];
	$out['build']['checked'] = $best['checked'];
	$exports = $sd->exports($id);
	$base = $sd->imageBase($id);
	foreach ($frames as $f) {
		$r = $f;
		$r['status'] = null;
		if (!is_game_frame($f)) {
			$r['status'] = 'other_module';
		} elseif ($f['offset'] == 0) {
			$r['status'] = 'no_address';
		} else {
			$rva = frame_rva($f, $exports);
			if ($rva === null) {
				$r['status'] = 'unknown_export';
			} else {
				$r['address'] = sprintf('0x%x', $base + $rva);
				$fn = $sd->functionAt($id, lookup_rva($f, $rva));
				if ($fn === null) {
					$r['status'] = 'outside_functions';
				} else {
					$r['function'] = sprintf('0x%x', $base + $fn['func']);
					$r['function_offset'] = $rva - $fn['func'];
					$r['name'] = $fn['name_text'];
					$r['source'] = $fn['source_text'];
					$r['score'] = $fn['score'];
					$r['evidence'] = $fn['evidence_text'];
					$r['return_address_ok'] = $f['frame'] == 1 ? null : $sd->isReturnAddress($id, $rva);
					$r['status'] = ($fn['source_text'] == 'none' || $fn['source_text'] == 'unnamed') ? 'unnamed' : 'named';
				}
			}
		}
		$out['frames'][] = $r;
	}
	return $out;
}
