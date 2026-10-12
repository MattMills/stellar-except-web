<?php
// StellarStellaris Exception Translator 2.0: names the stellaris.exe frames of an exception.txt
// using static data from stellar-fnmatch (no database, no executables on the server).

require_once __DIR__ . '/lib/config.php';
require_once __DIR__ . '/lib/translator.php';
require_once __DIR__ . '/lib/storage.php';

$config = stellar_config();
$this_page = 'exceptions';
$error = null;
$result = null;
$token = null;
$fresh_upload = false;
// absolute base path of the app, so links also work from a /cached/<token> permalink
$base_url = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'])), '/') . '/';

try {
	$sd = new SymbolData($config['data_dir']);
	// cached translations are redone when the data or the translator changes
	$data_stamp = $sd->stamp() . '/' . TRANSLATOR_VERSION;
} catch (Exception $e) {
	$sd = null;
	$error = 'The symbol data is not available on this server.';
}

function h($s)
{
	return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
}

if ($sd !== null) {
	$link = null;
	if (preg_match('#/cached/([A-Za-z0-9+/]+)#', $_SERVER['REQUEST_URI'], $m)) {
		$link = $m[1];
	} elseif (isset($_GET['cached'])) {
		// nginx rewrite of /cached/<token> to index.php?cached=<token>
		$link = $_GET['cached'];
	} elseif (isset($_GET['r'])) {
		$link = $_GET['r'];
	}
	if (isset($_FILES['file-input']) && $_FILES['file-input']['error'] !== UPLOAD_ERR_NO_FILE) {
		$f = $_FILES['file-input'];
		if ($f['error'] !== UPLOAD_ERR_OK) {
			$error = 'The upload failed, please try again.';
		} elseif ($f['size'] > $config['max_upload_bytes']) {
			$error = 'That file is too big for an exception.txt (over ' . round($config['max_upload_bytes'] / 1e6) . ' MB).';
		} elseif (strtolower(substr($f['name'], -4)) !== '.txt') {
			$error = "That doesn't look like exception.txt.";
		} else {
			$path = $f['tmp_name'];
			if ($config['store_uploads']) {
				$stored = store_upload($f['tmp_name'], $config);
				if ($stored === null) {
					$error = 'Could not store the upload, please try again.';
				} else {
					$path = $stored['path'];
					$token = permalink_token($stored['time']);
					$fresh_upload = true;
				}
			}
			if ($error === null) {
				$result = translate_report(parse_exception_text(file_get_contents($path)), $sd, $config);
				if ($token !== null) {
					cache_translation($path, $result, $data_stamp);
				}
			}
		}
	} elseif ($link !== null) {
		$up = find_upload($link, $config);
		if ($up === null) {
			$error = 'That link does not point to a stored exception.txt.';
		} else {
			$token = $link;
			$result = cached_translation($up['path'], $data_stamp);
			if ($result === null) {
				$result = translate_report(parse_exception_text(file_get_contents($up['path'])), $sd, $config);
				cache_translation($up['path'], $result, $data_stamp);
			}
		}
	}
}

$use_site = !empty($config['header']) && is_file($config['header']);
if ($use_site) {
	include $config['header'];
} else {
	?><!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<title>Stellaris Exception Translator</title>
	<meta name="viewport" content="width=device-width">
	<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" crossorigin="anonymous">
</head>
<body>
<?php
}
?>
<style>
	.fn-name { font-family: SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.85em; word-break: break-all; }
	.addr { font-family: SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.85em; white-space: nowrap; }
	.unnamed { font-style: italic; opacity: 0.8; }
</style>
<div class="container-fluid px-4">
	<p>Upload the <code>exception.txt</code> that Stellaris writes when it crashes on Windows, and this page names the game functions in its stack trace. It works for the 64-bit Steam and GOG builds from 2.3.0 on.</p>
	<form enctype="multipart/form-data" method="POST" action="<?= h($base_url) ?>">
		<input type="hidden" name="MAX_FILE_SIZE" value="<?= (int)$config['max_upload_bytes'] ?>" />
		<div class="mb-3">
			<label for="file-input" class="form-label">exception.txt to translate</label>
			<div class="input-group">
				<input class="form-control" type="file" id="file-input" name="file-input" accept=".txt">
				<button type="submit" class="btn btn-primary">Translate</button>
			</div>
			<?php if ($config['store_uploads']) { ?>
			<div class="form-text">The file is kept on the server so the result gets a link you can share.</div>
			<?php } ?>
		</div>
	</form>
<?php
if ($error !== null) {
	?><div class="alert alert-danger"><?= h($error) ?></div><?php
} elseif ($result !== null && $result['error'] !== null) {
	?><div class="alert alert-warning"><?= h($result['error']) ?></div><?php
} elseif ($result !== null) {
	$a = $result['attr'];
	$b = $result['build'];
	$named = 0;
	$game = 0;
	foreach ($result['frames'] as $f) {
		if (!empty($f['game']) && $f['status'] !== 'no_address') {
			$game++;
			if ($f['status'] === 'named') {
				$named++;
			}
		}
	}
	?>
	<table class="table table-sm w-auto">
		<tr><th>Application</th><td><?= h(isset($a['Application']) ? $a['Application'] : '') ?></td></tr>
		<tr><th>Version</th><td><?= h($result['version']) ?></td></tr>
		<tr><th>Date/Time</th><td><?= h(isset($a['Date/Time']) ? $a['Date/Time'] : '') ?></td></tr>
		<tr><th>Build</th><td><?= h(ucfirst($b['platform'])) ?> &middot; <?= h($b['build_string']) ?>
			<span class="text-muted">(<?= (int)$b['fit'] ?> of <?= (int)$b['checked'] ?> frames fit this build<?= $b['names'] === 'pdb' ? '; names from its own PDB' : '' ?>)</span></td></tr>
		<tr><th>Named</th><td><?= $named ?> of <?= $game ?> game frames</td></tr>
	</table>
	<?php if ($game == 0) { ?>
	<div class="alert alert-warning">No stellaris.exe frame in this report has an address: the crash reporter wrote <code>(function-name not available) (+ 0)</code>, or the crash happened entirely in other modules, so there is nothing to translate.</div>
	<?php } ?>
	<?php if ($b['checked'] > 0 && $b['fit'] * 2 < $b['checked']) { ?>
	<div class="alert alert-warning">The stack does not fit any known <?= h($result['version']) ?> build well (modified or unknown executable?), so the names below may be wrong.</div>
	<?php } ?>
	<?php if (count($result['candidates']) > 1) { ?>
	<p class="text-muted small">Other <?= h($result['version']) ?> builds checked:
		<?php foreach ($result['candidates'] as $c) { if ($c['id'] === $b['id']) continue; ?>
			<?= h($c['platform']) ?> <?= h($c['build_string']) ?> (<?= (int)$c['fit'] ?>/<?= (int)$c['checked'] ?>);
		<?php } ?></p>
	<?php } ?>
	<pre><?= h($result['exception']) ?></pre>
	<?php if ($result['loops_removed'] > 0) { ?>
	<div class="alert alert-danger">Possible loop in the stack trace: <?= (int)$result['loops_removed'] ?> repeated frames were collapsed (see the Loops column).</div>
	<?php } ?>
	<table class="table table-sm table-hover">
		<thead><tr>
			<?php if ($result['loops_removed'] > 0) { ?><th>Loops</th><?php } ?>
			<th>#</th><th>Module</th><th>Symbol (+ offset)</th><th>Address</th><th>Function</th><th>Name</th><th>Source</th>
		</tr></thead>
		<tbody>
		<?php foreach ($result['frames'] as $f) {
			$src = '';
			$name = '';
			switch ($f['status']) {
				case 'named':
					$name = '<span class="fn-name">' . h($f['name']) . '</span>';
					if ($f['source'] === 'pdb') {
						$src = '<span class="badge bg-success">PDB</span>';
					} elseif ($f['source'] === 'funclet') {
						$src = '<span class="badge bg-info text-dark" title="C++ exception handling code of the named function">EH funclet</span>';
					} else {
						$cls = $f['score'] >= 5 ? 'bg-primary' : ($f['score'] >= 2 ? 'bg-secondary' : 'bg-warning text-dark');
						$src = '<span class="badge ' . $cls . '" title="' . h('matched signatures: ' . $f['evidence']) . '">matched ' . h(number_format($f['score'], 1)) . '</span>';
					}
					break;
				case 'unnamed':
					$name = '<span class="fn-name unnamed">' . h($f['name'] !== null ? $f['name'] : '[no name]') . '</span>';
					$src = '<span class="badge bg-dark" title="No PDB of any build names this function">no name</span>';
					break;
				case 'no_address':
					$src = '<span class="text-muted small">no address in report</span>';
					break;
				case 'unknown_export':
					$src = '<span class="text-muted small">unknown export</span>';
					break;
				case 'outside_functions':
					$src = '<span class="text-muted small">not inside a known function</span>';
					break;
			}
			$loop = isset($f['loop_count']) ? (int)$f['loop_count'] : 1;
			?>
			<tr>
				<?php if ($result['loops_removed'] > 0) { ?><td class="<?= $loop >= $config['loop_threshold'] ? 'table-danger' : '' ?>"><?= $loop ?></td><?php } ?>
				<td><?= (int)$f['frame'] ?></td>
				<td><?= !empty($f['module_inferred']) ? '<span class="text-muted" title="The report leaves the module empty; the symbol is a stellaris.exe export">stellaris.exe</span>' : h($f['module']) ?></td>
				<td><?= h($f['symbol']) ?> <?= $f['location'] !== null ? '(' . h($f['location']) . ')' : '(' . h($f['sign']) . ' ' . (int)$f['offset'] . ')' ?></td>
				<td class="addr"><?= isset($f['address']) ? h($f['address']) : '' ?></td>
				<td class="addr"><?= isset($f['function']) ? h($f['function']) . ' +0x' . dechex($f['function_offset']) : '' ?></td>
				<td><?= $name ?></td>
				<td><?= $src ?></td>
			</tr>
		<?php } ?>
		</tbody>
	</table>
	<p class="text-muted small">Names come from the PDB files that ship with the GOG builds (and some early Steam builds). Steam builds are matched to them function by function with <a href="https://github.com/MattMills/stellar-fnmatch">stellar-fnmatch</a>; the score is the weighted number of matching signatures. A "no name" function exists in the PDB builds too, but no PDB names it (for example code from libraries linked without symbols); it is described by the named functions it calls or is called by.</p>
	<?php if ($token !== null) { ?>
	<p>Link to this result: <a href="<?= h($base_url . 'cached/' . $token) ?>"><?= h($base_url . 'cached/' . $token) ?></a></p>
	<?php } ?>
<?php
}
?>
</div>
<?php
if ($use_site && !empty($config['footer']) && is_file($config['footer'])) {
	include $config['footer'];
} else {
	?></body></html><?php
}
if ($fresh_upload && $token !== null) {
	?><script>history.replaceState(null, '', <?= json_encode($base_url . 'cached/' . $token) ?>);</script><?php
}
