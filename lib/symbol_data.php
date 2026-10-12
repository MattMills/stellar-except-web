<?php
// Read-only access to the static data written by `stellar-fnmatch webdata` (see its
// src/webdata.rs for the file formats). Lookups are binary searches with fseek, so a request
// reads a few kilobytes no matter how large the data set is.

class SymbolData
{
	const NONE = 4294967295;
	const REC = 24; // bytes per function record
	const SOURCES = array(0 => 'none', 1 => 'pdb', 2 => 'matched', 3 => 'funclet', 4 => 'unnamed');

	private $dir;
	private $builds = array();
	private $versions = array();
	private $exports = array();
	private $handles = array();
	private $counts = array();

	public function __construct($dir)
	{
		$this->dir = rtrim($dir, '/');
		$json = @file_get_contents($this->dir . '/builds.json');
		if ($json === false) {
			throw new RuntimeException('symbol data not found in ' . $this->dir);
		}
		$data = json_decode($json, true);
		foreach ($data['builds'] as $b) {
			$this->builds[$b['id']] = $b;
		}
		$this->versions = $data['versions'];
	}

	// Changes whenever a new data set is deployed (used to invalidate cached translations).
	public function stamp()
	{
		return (string)@filemtime($this->dir . '/builds.json');
	}

	public function versions()
	{
		return array_keys($this->versions);
	}

	// Build ids for a version string, Steam builds first.
	public function candidates($version)
	{
		return isset($this->versions[$version]) ? $this->versions[$version] : array();
	}

	public function build($id)
	{
		return isset($this->builds[$id]) ? $this->builds[$id] : null;
	}

	public function exports($id)
	{
		if (!isset($this->exports[$id])) {
			$j = @file_get_contents($this->dir . '/builds/' . $id . '.exports.json');
			$this->exports[$id] = $j === false ? array() : json_decode($j, true);
		}
		return $this->exports[$id];
	}

	private function handle($name)
	{
		if (!isset($this->handles[$name])) {
			$fh = @fopen($this->dir . '/' . $name, 'rb');
			if ($fh === false) {
				throw new RuntimeException('cannot open ' . $name);
			}
			$this->handles[$name] = $fh;
		}
		return $this->handles[$name];
	}

	// Number of records in a file with an 8-byte header "XXXX" + u32 count.
	private function count($name)
	{
		if (!isset($this->counts[$name])) {
			$fh = $this->handle($name);
			fseek($fh, 4);
			$this->counts[$name] = unpack('V', fread($fh, 4))[1];
		}
		return $this->counts[$name];
	}

	public function name($nid)
	{
		if ($nid === self::NONE || $nid === null) {
			return null;
		}
		$idx = $this->handle('names.idx');
		fseek($idx, 8 + 4 * $nid);
		$o = unpack('Vstart/Vend', fread($idx, 8));
		if ($o['end'] <= $o['start']) {
			return '';
		}
		$dat = $this->handle('names.dat');
		fseek($dat, $o['start']);
		return fread($dat, $o['end'] - $o['start']);
	}

	private function record($fh, $i)
	{
		fseek($fh, 16 + self::REC * $i);
		return unpack('Vstart/Vend/Vfunc/Vname/Vevidence/vscore/Csource/Ckind', fread($fh, self::REC));
	}

	// The function chunk containing $rva in build $id, with its name, or null.
	public function functionAt($id, $rva)
	{
		$file = 'builds/' . $id . '.funcs';
		$n = $this->count($file);
		$fh = $this->handle($file);
		$lo = 0;
		$hi = $n - 1;
		$best = -1;
		while ($lo <= $hi) {
			$mid = ($lo + $hi) >> 1;
			$r = $this->record($fh, $mid);
			if ($r['start'] <= $rva) {
				$best = $mid;
				$lo = $mid + 1;
			} else {
				$hi = $mid - 1;
			}
		}
		if ($best < 0) {
			return null;
		}
		$r = $this->record($fh, $best);
		if ($rva >= $r['end']) {
			return null;
		}
		$r['name_text'] = $this->name($r['name']);
		$r['evidence_text'] = $this->name($r['evidence']);
		$r['source_text'] = self::SOURCES[$r['source']];
		$r['score'] = $r['score'] / 100.0;
		return $r;
	}

	public function imageBase($id)
	{
		$fh = $this->handle('builds/' . $id . '.funcs');
		fseek($fh, 8);
		return unpack('P', fread($fh, 8))[1];
	}

	// Is $rva the address right after a call instruction in build $id?
	public function isReturnAddress($id, $rva)
	{
		$file = 'builds/' . $id . '.rets';
		$n = $this->count($file);
		$fh = $this->handle($file);
		$lo = 0;
		$hi = $n - 1;
		while ($lo <= $hi) {
			$mid = ($lo + $hi) >> 1;
			fseek($fh, 8 + 4 * $mid);
			$v = unpack('V', fread($fh, 4))[1];
			if ($v == $rva) {
				return true;
			}
			if ($v < $rva) {
				$lo = $mid + 1;
			} else {
				$hi = $mid - 1;
			}
		}
		return false;
	}
}
