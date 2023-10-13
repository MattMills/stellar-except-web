<?php

$this_page = 'exceptions';
require_once('/var/www/html/stellar-web/header.php');
require_once('capstone.php');
require_once('fn2hash.php');
require_once('simple_profile.php');

$loop_detected = False;

$supported_versions = array('3.4.3', '3.4.4', '3.4.5', '3.5.1', '3.5.2', '3.5.3', '3.6.0', '3.6.1', '3.7.2', '3.7.3', '3.7.4', '3.8.1', '3.8.2', '3.8.3', '3.8.4');
$field_types = array( //https://github.com/cmu-sei/pharos/blob/master/tools/fn2hash/fn2hash.pod
	'pic_hash', 
	'composite_pic_hash',
	'mnemonic_hash', 
	'mnemonic_count_hash', 
	'mnemonic_category_hash',
	'mnemonic_category_count_hash',
);
prof_flag('start');
?>

<div class="container-flex mx-5">
	
	<div class="row"><p>This app will try to give you more info about an exception.txt from Stellaris on Windows on Steam. It is intended to help troubleshoot a crash.</p></div>
	<div class="row">Currently supported versions: <?php foreach($supported_versions as $v){ echo "$v "; } ?></div>
        <div class="row"><div class="alert alert-danger"><h4>This is a prototype under development. If you have issues please say something in Discord (link above)</h4></div></div>
	<div class="row">&nbsp;</div>
	<form enctype="multipart/form-data" method="POST" action='/'>
	<input type="hidden" name="MAX_FILE_SIZE" value="10000000" />
        <div id="file-open-container" class="col-12 align-self-center drop_zone">
        	<div class="mb-3">
                	<label for="file-input" class="form-label">Select exception.txt file to translate</label>
                        <div class="input-group">
                        	<input class="form-control" type="file" id="file-input" name="file-input">
                                <button id="file-input-button" type="submit" class="btn btn-primary">Upload</button>
                        </div>
                </div>

        </div>
	</form>
	<div class="row justify-content-md-center">
<?php

$cache_data = explode('/cached/', $_SERVER['REQUEST_URI']);

if(isset($cache_data[1])){
	$cache_mode = True;
	$cache_data = $cache_data[1];
}else{
	$cache_mode = False;
}


if(isset($_FILES['file-input'])){

	if(substr($_FILES['file-input']['name'], -4) != '.txt'){
		?><pre>That doesn't look like exception.txt, do you want to try again?</pre><?
		exit();
	}elseif($_FILES['file-input']['size'] > 10000000){
		?><pre>File you upload is too big (>10MB), rejected. Exception.txt should be a few MB at most</pre><?
		exit();
	}
	$timestamp = time();
	$dest_folder = "./exceptions/" . date('Y/m/d/', $timestamp);
	$dest_filename = $dest_folder . $timestamp . '_' . $_SERVER['REMOTE_ADDR'] . '.txt';
	@mkdir($dest_folder, 0777, true);

	if (@move_uploaded_file($_FILES['file-input']['tmp_name'], $dest_filename)) {
		?><pre>Successfully received file upload, parsing</pre><?
	}else{
		?><pre>File upload failed, try again or contact me on discord</pre><?
		exit();
	}

}else{
	if($cache_mode == False){
		exit();
	}else{
		$timestamp =base64_decode($cache_data . '==');

		if(!is_numeric($timestamp)){
			echo 'EXIT';
			exit();
		}

		$date = date('Y/m/d/', $timestamp);

		$dest_filename = glob("./exceptions/" . $date . $timestamp . '_*.txt');
		$cache_filename = glob("./exceptions/" . $date . $timestamp . '_*.txt.cached');

		if($dest_filename === False){
			exit();
		}
		$dest_filename = $dest_filename[0];
		$cache_filename = @$cache_filename[0];
	}
}

if(isset($cache_filename) && $cache_filename != null){
        $json = json_decode(file_get_contents($cache_filename), True);
	$stack = $json['stack'];
	$attr = $json['attr'];
	$exception = $json['exception'];
	$orig_stack_length = $json['orig_stack_length'];
	$deduped_stack_length = $json['deduped_stack_length'];

}else{

	prof_flag('parse_stack');
	$stack_output = parse_stack($dest_filename);
	$stack = $stack_output['stack'];
	$orig_stack_length = count($stack);
	prof_flag('dedupe_parsed_stack');
	$stack = dedupe_parsed_stack($stack);
	$deduped_stack_length = count($stack);

	$attr = $stack_output['attr'];
	$exception = $stack_output['exception'];

}

	
	if($attr['Application'] != 'Stellaris'){
		?><pre>Error: Unsupported application (Not Stellaris)</pre><?
		exit();
	}elseif(!in_array($attr['Version'], $supported_versions)){
		?><pre>Error: Unsupported version</pre><?
		exit();
	}elseif(count($stack) == 0){
		?><pre>Error: No stack trace found in file?</pre><?
		exit();
	}




?>
	</div>
<table class="table" data-color-mode="dark" data-dark-theme="dark">
<tr><td class="th">Application</td><td><?=htmlspecialchars($attr['Application'])?></td></tr>
<tr><td class="th">Version</td><td><?=htmlspecialchars($attr['Version'])?></td></tr>
<tr><td class="th">Date/Time</td><td><?=htmlspecialchars($attr['Date/Time'])?></td></tr>
</table>
<pre><?=htmlspecialchars($exception)?></pre>
<?php 
       if($orig_stack_length-$deduped_stack_length > 0){
	       $loop_detected = True;
	        ?><div class="alert alert-danger">WARNING: Possible loop detected in stacktrace, removed <?=($orig_stack_length-$deduped_stack_length);?> duplicate frames</div><?php
	}
?>
<table class="table" data-color-mode="dark" data-dark-theme="dark">
<tr>
 <?=($loop_detected ? "<th>Loops</th>" : "");?>

<th>Frame #</th>
<th>Module</th>
<th>Symbol</th>
<th>Offset</th>
<th>Real addr</th>
<?/*<th>Func Start</th>*/?>
<th>Translation</th>
<th>Method</th>
</tr>
<?php

	$game_version = $attr['Version'];
if(!isset($cache_filename) || $cache_filename == null){

	$steam_exec = $exec_file[$game_version]['steam']['windows'];
	$steam_objdump = $objdump[$game_version]['steam']['windows']['exports'];
	$steam_obdjump_func = $objdump[$game_version]['steam']['windows']['functions'];
	$func_sigs = $func_sigs[$game_version]['gog']['windows'];

	$base = $exec_addr[$game_version]['steam']['windows']['base'];
	$code_offset = $exec_addr[$game_version]['steam']['windows']['offset'];
	prof_flag('data_load_start');
	$func_sigs_arr = load_func_sigs($func_sigs);
	prof_flag('data_load_func_sigs');
	$known_symbols = load_known_symbols($objdump[$game_version]['steam']['windows']['exports']);
	prof_flag('data_load_end');

	foreach($stack as $key => $f){
		//prof_flag('frame_' . $key);
		$stack[$key]['real_offset'] = Null;
		$stack[$key]['translated_symbol'] = Null;
		$stack[$key]['method'] = 'no_attempt';

		if($f['module'] != 'stellaris.exe'){
			$stack[$key]['method'] = 'module_not_stellaris.exe';
			continue;
		}
		if(trim($f['offset']) == '+ 0'){
			$stack[$key]['method'] = '0_offset';
			continue;
		}

		$matching = find_known_symbol($f['module'], $f['symbol']);
		$stack[$key]['matching'] = $matching;

		if($matching['symbol'] === Null){
			$stack[$key]['method'] = 'no_known_symbol';
			continue;
		}

		$stack[$key]['real_offset'] = parse_exception_offset($f['offset'], $matching['addr'], $base);

		if($stack[$key]['real_offset'] === Null){
			$stack[$key]['method'] = 'failed_parse_real_offset';
			continue;
		}
		$fn = find_fn_start_end($stack[$key]['real_offset']);

		$stack[$key]['fn'] = $fn;

		if($fn['start'] == $stack[$key]['real_offset']){
			$stack[$key]['method'] = 'no_fn_start_end';
			continue;
		}

		//$steam_match = find_match_in_fn2hash_csv($fn['start'], $fn2hash_files[$attr['Version']]['steam']['windows'], $fn2hash_fields['fn_addr']);
		//$stack[$key]['steam_match'] = $steam_match;


		//if($steam_match === Null){
		//	$stack[$key]['method'] = 'no_steam_match';
		//	continue;
		//}
		
		
		foreach($field_types as $match_field){ //Go through all hash types to look for matching fns.
		//$gog_match = find_match_in_fn2hash_csv($steam_match[$match_field], $fn2hash_files[$attr['Version']]['gog']['windows'], $fn2hash_fields[$match_field]);
			$gog_match = find_match_in_fn2hash_db($attr['Version'], $fn['start'], $match_field);
			$stack[$key]['gog_match'] = $gog_match;

			if($gog_match === Null){
				continue;
			}

			$function_match = $gog_match['symbol'];  //find_match_in_addr_to_symbol($gog_match['fn_addr'], $addr_to_symbol_files[$attr['Version']]['gog']['windows']);
			if($function_match !== null){
				$stack[$key]['function_match'] = $function_match;
				$stack[$key]['translated_symbol'] = "{$function_match} ({$gog_match['num_bytes']}b / {$gog_match['num_instructions']}i)";
				$stack[$key]['method'] = "fn2hash_$match_field";
				break;
			
			}
		}
		if($gog_match === Null || $function_match === Null){
			$stack[$key]['method'] = 'no_fn2hash_match';
		}else{
			continue; // Match found via fn2hash
		}
		/*
			if($fn['start'] == $stack[$key]['real_offset']){
				$stack[$key]['translated_symbol'] = '(No known symbol)';
			}elseif($steam_match === null){
				$stack[$key]['translated_symbol'] = "(No steam fn match) (0x" . dechex($fn['start']) ." / {$fn['relative_start']}rs / {$fn['relative_end']}re / {$fn['size']}b)";
			}else{
				$stack[$key]['translated_symbol'] = "(Unable to lookup fn addr) ({$steam_match['num_bytes']}b / {$steam_match['num_instructions']}i)";
			}
		 */
		
	}
	prof_flag('post_fn2hash');
	foreach($stack as $key => $f){
		if($f['translated_symbol'] !== Null){
			continue; // If we already have a good match skip capstone
		}
		if(!isset($f['fn'])){
			continue; // If we can't even find a matching function in the executable, we have nothing to go off of.
		}

		prof_flag('frame_capstone_'.$key);
		$cs = init_capstone();
		$result = capstone_get_disasm($cs, $steam_exec, ($f['fn']['start']-$base)+$code_offset, 50);

		$func_bytes = array();
		$func_bytes_no_mem = array();

		foreach($result as $kr => $r){
			//echo "0x" . dechex($r->address) . ': ' . $r->mnemonic . "\t" . $r->op_str . "  ";
			$these_bytes = array();

			foreach($r->bytes as $kb => $b){
				$str = dechex($b);
				if(strlen($str) == 1) $str = "0" . $str;
				
				$these_bytes[] = $str;
				$these_bytes_mask[] = "??";
			}

			$oper_mem = False;
			if(isset($r->detail->operands)){
				foreach($r->detail->operands as $k => $oper){
					if($oper->type == 'mem'){
						$oper_mem = True;
					}
				}
			}
			
			$func_bytes[] = $these_bytes;
			if($oper_mem === False){
				$func_bytes_no_mem[] = $these_bytes;
			}else{
				$func_bytes_no_mem[] = $these_bytes_mask;
			}

			if(in_array('ret', $r->detail->groups)){
				break;
			}
		}

		$byte_str = "";
		foreach($func_bytes as $kb => $bytes){
			foreach($bytes as $key2 => $b){
				$byte_str .= "$b ";
			}
		
		}

		$bytes_no_mem = array();
		$bytes_no_mem_flat = array();
		$good_bytes = 0;
		foreach($func_bytes_no_mem as $kb => $bytes){
			$this_byte_str = "";
			foreach($bytes as $key2 => $b){
				$this_byte_str .= "$b ";
				$bytes_no_mem_flat[] = "$b";
				if($b != "??") $good_bytes++;
			}
			$bytes_no_mem[] = trim($this_byte_str);
		}
		

		$matches = array();
		$possible_matches = array();
		foreach($func_sigs_arr as $kl => $line){
			if(stristr($line, trim($byte_str))){
				$matches[] = $line;
				continue;
			}
			$match = True;

			if(trim($line) == "") continue;

			$e = explode("###", $line);

			$e2 = explode(" ", trim($e[1]));

			$seq_match = 0;
			foreach($e2 as $position => $input_byte){
				if($position >= count($bytes_no_mem_flat)){
					break;
				}
				$test_byte = $bytes_no_mem_flat[$position];
				if($test_byte == "??"){
					continue;
				}
				if($test_byte == $input_byte){
					$seq_match++;
				}
			}

			if($seq_match > count($bytes_no_mem_flat)/4){
				$possible_matches[$line] = $seq_match;
			}
		}

		if(count($matches) == 1){
			$e = explode("###", $matches[0]);
			$stack[$key]['translated_symbol'] = trim($e[0]);
			$stack[$key]['method'] = 'capstone_unique';
		}elseif(count($matches) > 1){
			$stack[$key]['translated_symbol'] = "Multiple matches (";
			foreach($matches as $k => $match){
				$e = explode("###", $match);
				$stack[$key]['translated_symbol'] .= trim($e[0]) . ", ";
			}
			$stack[$key]['translated_symbol'] .= ")";
			$stack[$key]['method'] = 'capstone_too_many';
		}else{
			$max = 0;
			$max_k = Null;
			foreach($possible_matches as $k => $match){
				if($match > $max){ 
					$max = $match;
					$max_k = $k;
				}
			}
			$e = explode('###', $max_k);
			if($max > count($bytes_no_mem_flat)/2){
				$stack[$key]['translated_symbol'] = 'Most likely - ' .trim($e[0]) . ' - ';
				$stack[$key]['method'] = 'capstone_partial_match';
			}else{
				$stack[$key]['method'] = 'no_fn2match_no_capstone';
			}
		}
	}

	$cache = array('stack' => $stack, 'attr' => $attr, 'exception' => $exception, 'orig_stack_length' => $orig_stack_length, 'deduped_stack_length' => $deduped_stack_length);
	file_put_contents($dest_filename . '.cached', json_encode($cache));
}

	foreach($stack as $key => $f){
		if($f['translated_symbol'] === Null){
			$f['translated_symbol'] = "No Symbol match ({$f['method']})";
		}
?>
<tr>
<?=($loop_detected && $f['loop_count'] > 5) ? "<td class='table-danger'>{$f['loop_count']}</td>" : "";?>
<?=($loop_detected && $f['loop_count'] <= 5) ? "<td>{$f['loop_count']}</td>" : "";?>
<td><?=htmlspecialchars($f['frame'])?></td>
<td><?=htmlspecialchars($f['module'])?></td>
<td><?=htmlspecialchars($f['symbol'])?></td>
<td><?=htmlspecialchars($f['offset'])?></td>
<td><?=($f['real_offset'] === Null ? "" : "0x".dechex($f['real_offset']))?></td>
<? /*<td><?=($f['real_offset'] === Null ? "" : '0x'.dechex($f['fn']['start']))?></td>*/ ?>
<td><?=htmlspecialchars($f['translated_symbol'])?></td>
<td><?=$f['method']?></td>
</tr>
<?php
	}
?>
</table>

<?php
?>





</div>
<?php
include('/var/www/html/stellar-web/footer.php');
prof_flag('complete');
//prof_print();
if(!$cache_mode){
?>
<script>
$('body').ready(function (){
	history.pushState(null, null, window.location.href + 'cached/<?=substr(base64_encode($timestamp), 0, -2)?>');
});
</script>

<? }
