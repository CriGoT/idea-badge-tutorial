<?php

require 'vendor/autoload.php';

session_start();

$client = new \GuzzleHttp\Client();

$res = $client->request('POST', 'https://idea.org.uk/api/result', [
	'http_errors' => false,
	'headers' => [
		'Authorization' => 'Bearer ' . $_SESSION['oauth2_access_token']
	],
	'json' => [
		'result' => 'pass', // Or fail, if the badge was failed
	]
]);

$response = json_decode($res->getBody());

die(print_r($response));

header("Location: logout.php?return_url=$return_url");