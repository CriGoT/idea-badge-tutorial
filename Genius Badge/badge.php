<?php

require 'vendor/autoload.php';

session_start();

$client = new \GuzzleHttp\Client();

$res = $client->request('GET', 'https://idea.org.uk/api/user', [
	'http_errors' => false,
	'headers' => [
		'Authorization' => 'Bearer ' . $_SESSION['oauth2_access_token']
	]
]);

$user = json_decode($res->getBody());

?>
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<title>Genius Badge</title>
</head>
<body>
	<h1>Welcome, <?=$user->name?></h1>
	<p>
		<img src="<?=$user->image_url?>" alt="Profile avatar image">
	</p>
	<p>
		Are you a genius? <a href="badge-completed.php">Click here!</a>
	</p>
</body>
</html>