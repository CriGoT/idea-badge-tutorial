<?php

session_start();

session_destroy();

$return_url = ($_GET['return_url'] != NULL) ? $_GET['return_url'] : 'https://www.idea.org.uk/';

header("Location: $return_url");
