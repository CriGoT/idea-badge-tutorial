<?php

session_start();

$state = hash('sha256', microtime(true) . rand());
$_SESSION['oauth2_state'] = $state;

$params = [
   'response_type' => 'code',
   'client_id' => getenv('GENIUS_BADGE_CLIENT_ID'),
   'redirect_uri' => getenv('GENIUS_BADGE_REDIRECT_URI'),
   'prompt' => 'none',
   'scope' => 'openid',
   'state' => $state
];

$authUrl = 'https://idea.eu.auth0.com/authorize?' . http_build_query($params);

header("Location: $authUrl");
