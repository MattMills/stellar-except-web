<?php

date_default_timezone_set('UTC');

$dbh = pg_pconnect('user=postgres dbname=stellar-fnaddr ');
assert_options(ASSERT_CALLBACK, function($parameter){
        error_log('Assert Failed: ' . print_r($parameter, True));
        throw new Exception('Assert failed');
});

